// Copyright 2021 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package catalyst implements the temporary eth1/eth2 RPC integration.
package catalyst

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/beacon"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/rpc"
)

// Register adds the engine API to the full node.
func Register(stack *node.Node, backend *eth.Ethereum) error {
	log.Warn("Engine API enabled", "protocol", "eth")
	stack.RegisterAPIs([]rpc.API{
		{
			Namespace:     "engine",
			Service:       NewConsensusAPI(backend),
			Authenticated: true,
		},
	})
	return nil
}

const (
	// invalidBlockHitEviction is the number of times an invalid block can be
	// referenced in forkchoice update or new payload before it is attempted
	// to be reprocessed again.
	invalidBlockHitEviction = 128

	// invalidTipsetsCap is the max number of recent block hashes tracked that
	// have lead to some bad ancestor block. It's just an OOM protection.
	invalidTipsetsCap = 512

	// beaconUpdateStartupTimeout is the time to wait for a beacon client to get
	// attached before starting to issue warnings.
	beaconUpdateStartupTimeout = 30 * time.Second

	// beaconUpdateExchangeTimeout is the max time allowed for a beacon client to
	// do a transition config exchange before it's considered offline and the user
	// is warned.
	beaconUpdateExchangeTimeout = 2 * time.Minute

	// beaconUpdateConsensusTimeout is the max time allowed for a beacon client
	// to send a consensus update before it's considered offline and the user is
	// warned.
	beaconUpdateConsensusTimeout = 30 * time.Second

	// beaconUpdateWarnFrequency is the frequency at which to warn the user that
	// the beacon client is offline.
	beaconUpdateWarnFrequency = 5 * time.Minute
)

type ConsensusAPI struct {
	eth *eth.Ethereum

	remoteBlocks *headerQueue  // Cache of remote payloads received
	localBlocks  *payloadQueue // Cache of local payloads generated

	// The forkchoice update and new payload method require us to return the
	// latest valid hash in an invalid chain. To support that return, we need
	// to track historical bad blocks as well as bad tipsets in case a chain
	// is constantly built on it.
	//
	// There are a few important caveats in this mechanism:
	//   - The bad block tracking is ephemeral, in-memory only. We must never
	//     persist any bad block information to disk as a bug in Geth could end
	//     up blocking a valid chain, even if a later Geth update would accept
	//     it.
	//   - Bad blocks will get forgotten after a certain threshold of import
	//     attempts and will be retried. The rationale is that if the network
	//     really-really-really tries to feed us a block, we should give it a
	//     new chance, perhaps us being racey instead of the block being legit
	//     bad (this happened in Geth at a point with import vs. pending race).
	//   - Tracking all the blocks built on top of the bad one could be a bit
	//     problematic, so we will only track the head chain segment of a bad
	//     chain to allow discarding progressing bad chains and side chains,
	//     without tracking too much bad data.
	invalidBlocksHits map[common.Hash]int           // Emhemeral cache to track invalid blocks and their hit count
	invalidTipsets    map[common.Hash]*types.Header // Ephemeral cache to track invalid tipsets and their bad ancestor
	invalidLock       sync.Mutex                    // Protects the invalid maps from concurrent access

	// Geth can appear to be stuck or do strange things if the beacon client is
	// offline or is sending us strange data. Stash some update stats away so
	// that we can warn the user and not have them open issues on our tracker.
	lastTransitionUpdate time.Time
	lastTransitionLock   sync.Mutex
	lastForkchoiceUpdate time.Time
	lastForkchoiceLock   sync.Mutex
	lastNewPayloadUpdate time.Time
	lastNewPayloadLock   sync.Mutex

	forkchoiceLock sync.Mutex // Lock for the forkChoiceUpdated method
}

// NewConsensusAPI creates a new consensus api for the given backend.
// The underlying blockchain needs to have a valid terminal total difficulty set.
func NewConsensusAPI(eth *eth.Ethereum) *ConsensusAPI {
	if eth.BlockChain().Config().TerminalTotalDifficulty == nil {
		log.Warn("Engine API started but chain not configured for merge yet")
	}
	api := &ConsensusAPI{
		eth:               eth,
		remoteBlocks:      newHeaderQueue(),
		localBlocks:       newPayloadQueue(),
		invalidBlocksHits: make(map[common.Hash]int),
		invalidTipsets:    make(map[common.Hash]*types.Header),
	}
	//eth.Downloader().SetBadBlockCallback(api.setInvalidAncestor)
	go api.heartbeat()

	return api
}

// ExchangeTransitionConfigurationV1 checks the given configuration against
// the configuration of the node.
func (api *ConsensusAPI) ExchangeTransitionConfigurationV1(config beacon.TransitionConfigurationV1) (*beacon.TransitionConfigurationV1, error) {
	log.Trace("Engine API request received", "method", "ExchangeTransitionConfiguration", "ttd", config.TerminalTotalDifficulty)
	if config.TerminalTotalDifficulty == nil {
		return nil, errors.New("invalid terminal total difficulty")
	}
	// Stash away the last update to warn the user if the beacon client goes offline
	api.lastTransitionLock.Lock()
	api.lastTransitionUpdate = time.Now()
	api.lastTransitionLock.Unlock()

	ttd := api.eth.BlockChain().Config().TerminalTotalDifficulty
	if ttd == nil || ttd.Cmp(config.TerminalTotalDifficulty.ToInt()) != 0 {
		log.Warn("Invalid TTD configured", "geth", ttd, "beacon", config.TerminalTotalDifficulty)
		return nil, fmt.Errorf("invalid ttd: execution %v consensus %v", ttd, config.TerminalTotalDifficulty)
	}
	if config.TerminalBlockHash != (common.Hash{}) {
		if hash := api.eth.BlockChain().GetCanonicalHash(uint64(config.TerminalBlockNumber)); hash == config.TerminalBlockHash {
			return &beacon.TransitionConfigurationV1{
				TerminalTotalDifficulty: (*hexutil.Big)(ttd),
				TerminalBlockHash:       config.TerminalBlockHash,
				TerminalBlockNumber:     config.TerminalBlockNumber,
			}, nil
		}
		return nil, fmt.Errorf("invalid terminal block hash")
	}
	return &beacon.TransitionConfigurationV1{TerminalTotalDifficulty: (*hexutil.Big)(ttd)}, nil
}

// GetPayloadV1 returns a cached payload by id.
func (api *ConsensusAPI) GetPayloadV1(payloadID beacon.PayloadID) (*beacon.ExecutableDataV1, error) {
	log.Trace("Engine API request received", "method", "GetPayload", "id", payloadID)
	data := api.localBlocks.get(payloadID)
	if data == nil {
		return nil, beacon.UnknownPayload
	}
	return data, nil
}

// computePayloadId computes a pseudo-random payloadid, based on the parameters.
func computePayloadId(headBlockHash common.Hash, params *beacon.PayloadAttributesV1) beacon.PayloadID {
	// Hash
	hasher := sha256.New()
	hasher.Write(headBlockHash[:])
	binary.Write(hasher, binary.BigEndian, params.Timestamp)
	hasher.Write(params.Random[:])
	hasher.Write(params.SuggestedFeeRecipient[:])
	var out beacon.PayloadID
	copy(out[:], hasher.Sum(nil)[:8])
	return out
}

// setInvalidAncestor is a callback for the downloader to notify us if a bad block
// is encountered during the async sync.
func (api *ConsensusAPI) setInvalidAncestor(invalid *types.Header, origin *types.Header) {
	api.invalidLock.Lock()
	defer api.invalidLock.Unlock()

	api.invalidTipsets[origin.Hash()] = invalid
	api.invalidBlocksHits[invalid.Hash()]++
}

// checkInvalidAncestor checks whether the specified chain end links to a known
// bad ancestor. If yes, it constructs the payload failure response to return.
func (api *ConsensusAPI) checkInvalidAncestor(check common.Hash, head common.Hash) *beacon.PayloadStatusV1 {
	api.invalidLock.Lock()
	defer api.invalidLock.Unlock()

	// If the hash to check is unknown, return valid
	invalid, ok := api.invalidTipsets[check]
	if !ok {
		return nil
	}
	// If the bad hash was hit too many times, evict it and try to reprocess in
	// the hopes that we have a data race that we can exit out of.
	badHash := invalid.Hash()

	api.invalidBlocksHits[badHash]++
	if api.invalidBlocksHits[badHash] >= invalidBlockHitEviction {
		log.Warn("Too many bad block import attempt, trying", "number", invalid.Number, "hash", badHash)
		delete(api.invalidBlocksHits, badHash)

		for descendant, badHeader := range api.invalidTipsets {
			if badHeader.Hash() == badHash {
				delete(api.invalidTipsets, descendant)
			}
		}
		return nil
	}
	// Not too many failures yet, mark the head of the invalid chain as invalid
	if check != head {
		log.Warn("Marked new chain head as invalid", "hash", head, "badnumber", invalid.Number, "badhash", badHash)
		for len(api.invalidTipsets) >= invalidTipsetsCap {
			for key := range api.invalidTipsets {
				delete(api.invalidTipsets, key)
				break
			}
		}
		api.invalidTipsets[head] = invalid
	}
	// If the last valid hash is the terminal pow block, return 0x0 for latest valid hash
	lastValid := &invalid.ParentHash
	if header := api.eth.BlockChain().GetHeader(invalid.ParentHash, invalid.Number.Uint64()-1); header != nil && header.Difficulty.Sign() != 0 {
		lastValid = &common.Hash{}
	}
	failure := "links to previously rejected block"
	return &beacon.PayloadStatusV1{
		Status:          beacon.INVALID,
		LatestValidHash: lastValid,
		ValidationError: &failure,
	}
}

// invalid returns a response "INVALID" with the latest valid hash supplied by latest or to the current head
// if no latestValid block was provided.
func (api *ConsensusAPI) invalid(err error, latestValid *types.Header) beacon.PayloadStatusV1 {
	currentHash := api.eth.BlockChain().CurrentBlock().Hash()
	if latestValid != nil {
		// Set latest valid hash to 0x0 if parent is PoW block
		currentHash = common.Hash{}
		if latestValid.Difficulty.BitLen() == 0 {
			// Otherwise set latest valid hash to parent hash
			currentHash = latestValid.Hash()
		}
	}
	errorMsg := err.Error()
	return beacon.PayloadStatusV1{Status: beacon.INVALID, LatestValidHash: &currentHash, ValidationError: &errorMsg}
}

// heartbeat loops indefinitely, and checks if there have been beacon client updates
// received in the last while. If not - or if they but strange ones - it warns the
// user that something might be off with their consensus node.
//
// TODO(karalabe): Spin this goroutine down somehow
func (api *ConsensusAPI) heartbeat() {
	// Sleep a bit on startup since there's obviously no beacon client yet
	// attached, so no need to print scary warnings to the user.
	time.Sleep(beaconUpdateStartupTimeout)

	var (
		offlineLogged time.Time
	)
	for {
		// Sleep a bit and retrieve the last known consensus updates
		time.Sleep(5 * time.Second)

		// If the network is not yet merged/merging, don't bother scaring the user
		ttd := api.eth.BlockChain().Config().TerminalTotalDifficulty
		if ttd == nil {
			continue
		}
		api.lastTransitionLock.Lock()
		lastTransitionUpdate := api.lastTransitionUpdate
		api.lastTransitionLock.Unlock()

		api.lastForkchoiceLock.Lock()
		lastForkchoiceUpdate := api.lastForkchoiceUpdate
		api.lastForkchoiceLock.Unlock()

		api.lastNewPayloadLock.Lock()
		lastNewPayloadUpdate := api.lastNewPayloadUpdate
		api.lastNewPayloadLock.Unlock()

		// If there have been no updates for the past while, warn the user
		// that the beacon client is probably offline
		if api.eth.BlockChain().Config().TerminalTotalDifficultyPassed || api.eth.Merger().TDDReached() {
			if time.Since(lastForkchoiceUpdate) > beaconUpdateConsensusTimeout && time.Since(lastNewPayloadUpdate) > beaconUpdateConsensusTimeout {
				if time.Since(lastTransitionUpdate) > beaconUpdateExchangeTimeout {
					if time.Since(offlineLogged) > beaconUpdateWarnFrequency {
						if lastTransitionUpdate.IsZero() {
							log.Warn("Post-merge network, but no beacon client seen. Please launch one to follow the chain!")
						} else {
							log.Warn("Previously seen beacon client is offline. Please ensure it is operational to follow the chain!")
						}
						offlineLogged = time.Now()
					}
					continue
				}
				if time.Since(offlineLogged) > beaconUpdateWarnFrequency {
					if lastForkchoiceUpdate.IsZero() && lastNewPayloadUpdate.IsZero() {
						log.Warn("Beacon client online, but never received consensus updates. Please ensure your beacon client is operational to follow the chain!")
					} else {
						log.Warn("Beacon client online, but no consensus updates received in a while. Please fix your beacon client to follow the chain!")
					}
					offlineLogged = time.Now()
				}
				continue
			} else {
				offlineLogged = time.Time{}
			}
		} else {
			if time.Since(lastTransitionUpdate) > beaconUpdateExchangeTimeout {
				if time.Since(offlineLogged) > beaconUpdateWarnFrequency {
					// Retrieve the last few blocks and make a rough estimate as
					// to when the merge transition should happen
					var (
						chain = api.eth.BlockChain()
						head  = chain.CurrentBlock()
						htd   = chain.GetTd(head.Hash(), head.NumberU64())
						eta   time.Duration
					)
					if head.NumberU64() > 0 && htd.Cmp(ttd) < 0 {
						// Accumulate the last 64 difficulties to estimate the growth
						var diff float64

						block := head
						for i := 0; i < 64; i++ {
							diff += float64(block.Difficulty().Uint64())
							if parent := chain.GetBlock(block.ParentHash(), block.NumberU64()-1); parent == nil {
								break
							} else {
								block = parent
							}
						}
						// Estimate an ETA based on the block times and the difficulty growth
						growth := diff / float64(head.Time()-block.Time()+1) // +1 to avoid div by zero
						if growth > 0 {
							if left := new(big.Int).Sub(ttd, htd); left.IsUint64() {
								eta = time.Duration(float64(left.Uint64())/growth) * time.Second
							} else {
								eta = time.Duration(new(big.Int).Div(left, big.NewInt(int64(growth))).Uint64()) * time.Second
							}
						}
					}
					var message string
					if htd.Cmp(ttd) > 0 {
						if lastTransitionUpdate.IsZero() {
							message = "Merge already reached, but no beacon client seen. Please launch one to follow the chain!"
						} else {
							message = "Merge already reached, but previously seen beacon client is offline. Please ensure it is operational to follow the chain!"
						}
					} else {
						if lastTransitionUpdate.IsZero() {
							message = "Merge is configured, but no beacon client seen. Please ensure you have one available before the transition arrives!"
						} else {
							message = "Merge is configured, but previously seen beacon client is offline. Please ensure it is operational before the transition arrives!"
						}
					}
					if eta == 0 {
						log.Warn(message)
					} else {
						log.Warn(message, "eta", common.PrettyAge(time.Now().Add(-eta))) // weird hack, but duration formatted doesn't handle days
					}
					offlineLogged = time.Now()
				}
				continue
			} else {
				offlineLogged = time.Time{}
			}
		}
	}
}
