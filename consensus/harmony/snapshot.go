package harmony

import (
	"bytes"
	"encoding/json"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	lru "github.com/hashicorp/golang-lru"
	"sort"
	"time"
)

// Snapshot is the state of the authorization voting at a given point in time.
type Snapshot struct {
	config   *params.HarmonyConfig // Consensus engine parameters to fine tune behavior
	sigcache *lru.ARCCache         // Cache of recent block signatures to speed up ecrecover

	Number  uint64                      `json:"number"`  // Block number where the snapshot was created
	Hash    common.Hash                 `json:"hash"`    // Block hash where the snapshot was created
	Signers map[common.Address]struct{} `json:"signers"` // Set of authorized signers at this moment
	Recents map[uint64]common.Address   `json:"recents"` // Set of recent signers for spam protections  //@keep，这个“最近”的定义是最新的len(Snapshot.Signers)/2 + 1个块
}

// signersAscending implements the sort interface to allow sorting a list of addresses
type signersAscending []common.Address

func (s signersAscending) Len() int           { return len(s) }
func (s signersAscending) Less(i, j int) bool { return bytes.Compare(s[i][:], s[j][:]) < 0 }
func (s signersAscending) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// method does not initialize the set of recent signers, so only ever use if for
// the genesis block.
func newSnapshot(config *params.HarmonyConfig, sigcache *lru.ARCCache, number uint64, hash common.Hash, signers []common.Address) *Snapshot {
	snap := &Snapshot{
		config:   config,
		sigcache: sigcache,
		Number:   number,
		Hash:     hash,
		Signers:  make(map[common.Address]struct{}),
		Recents:  make(map[uint64]common.Address),
	}
	for _, signer := range signers {
		snap.Signers[signer] = struct{}{}
	}
	return snap
}

// loadSnapshot loads an existing snapshot from the database.
func loadSnapshot(config *params.HarmonyConfig, sigcache *lru.ARCCache, db ethdb.Database, hash common.Hash) (*Snapshot, error) {
	blob, err := db.Get(append([]byte("harmony-"), hash[:]...))
	if err != nil {
		return nil, err
	}
	snap := new(Snapshot)
	if err := json.Unmarshal(blob, snap); err != nil {
		return nil, err
	}
	snap.config = config
	snap.sigcache = sigcache

	return snap, nil
}

// store inserts the snapshot into the database.
func (s *Snapshot) store(db ethdb.Database) error {
	blob, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return db.Put(append([]byte("harmony-"), s.Hash[:]...), blob)
}

// copy creates a deep copy of the snapshot, though not the individual votes.
func (s *Snapshot) copy() *Snapshot {
	cpy := &Snapshot{
		config:   s.config,
		sigcache: s.sigcache,
		Number:   s.Number,
		Hash:     s.Hash,
		Signers:  make(map[common.Address]struct{}),
		Recents:  make(map[uint64]common.Address),
	}
	for signer := range s.Signers {
		cpy.Signers[signer] = struct{}{}
	}
	for block, signer := range s.Recents {
		cpy.Recents[block] = signer
	}

	return cpy
}

func (s *Snapshot) apply(headers []*types.Header) (*Snapshot, error) {
	// Allow passing in no headers for cleaner code
	if len(headers) == 0 {
		return s, nil
	}
	// Sanity check that the headers can be applied
	//@keep，检查headers应该按照高度从小到达排序，
	for i := 0; i < len(headers)-1; i++ {
		if headers[i+1].Number.Uint64() != headers[i].Number.Uint64()+1 {
			return nil, errInvalidVotingChain
		}
	}
	//snapshot[i-1] 加上header[i] => 生产出snapshot[i]
	//@keep，检查基准的snap和第一个header是否是连续的。
	if headers[0].Number.Uint64() != s.Number+1 {
		return nil, errInvalidVotingChain
	}
	// Iterate through the headers and create a new snapshot
	snap := s.copy()

	var (
		start  = time.Now()
		logged = time.Now()
	)
	for i, header := range headers {
		// Remove any votes on checkpoint blocks
		number := header.Number.Uint64()
		if number%s.config.Epoch == 0 {
			//@keep，理论上不会header是不会跨epoch的，但是为了兼容这种情况，先
			log.Warn("snapshot apply, Cross epoch situation happen, need check", "snap", s, "headers", headers)
			for k, _ := range snap.Recents {
				delete(snap.Recents, k)
			}

			for signer, _ := range s.Signers {
				delete(snap.Signers, signer)
			}

			//从epoch header中取出signers列表
			newValidators := make([]common.Address, (len(header.Extra)-extraVanity-extraSeal)/common.AddressLength)
			for i := 0; i < len(newValidators); i++ {
				//copy出signer的列表
				copy(newValidators[i][:], header.Extra[extraVanity+i*common.AddressLength:])
			}

			for _, validator := range newValidators {
				snap.Signers[validator] = struct{}{}
			}

		} else {
			// Delete the oldest signer from the recent list to allow it signing again
			//Snapshot.Recents字段保存了最近出块的签名者和所出的块的高度。这个“最近”的定义是最新的len(Snapshot.Signers)/2 + 1个块。
			//我们先看一下代码是如何操作这个字段的
			if limit := uint64(len(snap.Signers)/2 + 1); number >= limit {
				delete(snap.Recents, number-limit)
			}
			// Resolve the authorization key and check against signers
			signer, err := ecrecover(header, s.sigcache)
			if err != nil {
				return nil, err
			}
			if _, ok := snap.Signers[signer]; !ok {
				return nil, errUnauthorizedSigner
			}
			for _, recent := range snap.Recents {
				if recent == signer {
					return nil, errRecentlySigned
				}
			}

			/*@keep，将当前块的高度和签名者加入Recents中
			比如目前有6个签名者，当前块的高度是10，那么高度为"10 - (6/2 + 1) = 6"的块将从Recents中删除，然后将高度为10的块和其签名者加入Recents中；
			处理一下个块即高度为11时，高度为7的块又会从Recents中删除，然后高度为11的块会被加入。
			总之，这个"最近"的基点是当前块的高度，囊括的范围为len(Snapshot.Signers)/2 + 1。
			*/
			snap.Recents[number] = signer
		}
		// If we're taking too much time (ecrecover), notify the user once a while
		if time.Since(logged) > 8*time.Second {
			log.Info("Reconstructing snapshot history", "processed", i, "total", len(headers), "elapsed", common.PrettyDuration(time.Since(start)))
			logged = time.Now()
		}
	}

	if time.Since(start) > 8*time.Second {
		log.Info("Reconstructed snapshot history", "processed", len(headers), "elapsed", common.PrettyDuration(time.Since(start)))
	}
	snap.Number += uint64(len(headers))
	snap.Hash = headers[len(headers)-1].Hash()

	return snap, nil
}

// signers retrieves the list of authorized signers in ascending order.
// @keep，signers 按照地址的bytes 大小排序。
func (s *Snapshot) signers() []common.Address {
	sigs := make([]common.Address, 0, len(s.Signers))
	for sig := range s.Signers {
		sigs = append(sigs, sig)
	}
	sort.Sort(signersAscending(sigs))
	return sigs
}

// @keep，使用区块高度来决定是否为inturn，还是outturn
// inturn returns if a signer at a given block height is in-turn or not.
func (s *Snapshot) inturn(number uint64, signer common.Address) bool {
	signers := s.signers()
	offset := number % uint64(len(signers))
	return signers[offset] == signer
}

func (s *Snapshot) indexOfSigner(signer common.Address) int {
	signers := s.signers()
	for idx, signer1 := range signers {
		if signer1 == signer {
			return idx
		}
	}
	return -1
}
