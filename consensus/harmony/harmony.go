package harmony

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	lru "github.com/hashicorp/golang-lru"
	"golang.org/x/crypto/sha3"
)

const (
	checkpointInterval = 1024 // Number of blocks after which to save the vote snapshot to the database
	inmemorySnapshots  = 128  // Number of recent vote snapshots to keep in memory
	inMemorySignatures = 4096 // Number of recent block signatures to keep in memory

	wiggleTime         = uint64(1) // Random delay (per signer) to allow concurrent signers
	initialBackOffTime = uint64(1) // second

	maxValidatorSize = 5
	safeSize         = maxValidatorSize*2/3 + 1
	consensusSize    = maxValidatorSize*2/3 + 1
)

// Clique proof-of-authority protocol constants.
var (
	epochLength = uint64(30000) // Default number of blocks after which to checkpoint and reset the pending votes

	extraVanity = 32                     // Fixed number of extra-data prefix bytes reserved for signer vanity
	extraSeal   = crypto.SignatureLength // Fixed number of extra-data suffix bytes reserved for signer seal

	uncleHash = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.

	diffInTurn = big.NewInt(2) // Block difficulty for in-turn signatures， InTurn 难度为2，NoTurn难度为1
	diffNoTurn = big.NewInt(1) // Block difficulty for out-of-turn signatures

	//defaultDifficulty  = common.Big1 // The default block defaultDifficulty in the harmony consensus
	timeOfFirstBlock   = uint64(0)
	confirmedBlockHead = []byte("confirmed-block-head")
)

var (
	// errUnknownBlock is returned when the list of signers is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")
	// errMissingVanity is returned if a block's extra-data section is shorter than
	// 32 bytes, which is required to store the signer vanity.
	errMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")
	// errMissingSignature is returned if a block's extra-data section doesn't seem
	// to contain a 65 byte secp256k1 signature.
	errMissingSignature = errors.New("extra-data 65 byte suffix signature missing")

	// errExtraValidators is returned if non-sprint-end block contain validator data in
	// their extra-data fields.
	errExtraValidators = errors.New("non-sprint-end block contains extra validator list")

	// errInvalidSpanValidators is returned if a block contains an
	// invalid list of validators (i.e. non divisible by 20 bytes).
	errInvalidSpanValidators = errors.New("invalid validator list on sprint end block")

	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")

	// errMismatchingCheckpointSigners is returned if a checkpoint block contains a
	// list of signers different than the one the local node calculated.
	errMismatchingCheckpointSigners = errors.New("mismatching signer list on checkpoint block")

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")

	// errInvalidDifficulty is returned if the difficulty of a block neither 1 or 2.
	errInvalidDifficulty = errors.New("invalid difficulty")

	// errWrongDifficulty is returned if the difficulty of a block doesn't match the
	// turn of the signer.
	errWrongDifficulty = errors.New("wrong difficulty")

	// errInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp + the minimum block period.
	errInvalidTimestamp = errors.New("invalid timestamp")

	// errInvalidVotingChain is returned if an authorization list is attempted to
	// be modified via out-of-range or non-contiguous headers.
	errInvalidVotingChain = errors.New("invalid voting chain")

	// errUnauthorizedSigner is returned if a header is signed by a non-authorized entity.
	errUnauthorizedSigner = errors.New("unauthorized signer")

	// errRecentlySigned is returned if a header is signed by an authorized entity
	// that already signed a header recently, thus is temporarily not allowed to.
	errRecentlySigned = errors.New("recently signed")

	// errCoinBaseMisMatch is returned if a header's coinbase do not match with signature
	errCoinBaseMisMatch = errors.New("coinbase do not match with signature")

	// ErrInvalidTimestamp is returned if the timestamp of a block is lower than
	ErrWaitForPrevBlock           = errors.New("wait for last block arrived")
	ErrMintFutureBlock            = errors.New("mint the future block")
	ErrMismatchSignerAndValidator = errors.New("mismatch block signer and validator")
	ErrInvalidBlockValidator      = errors.New("not my turn")
	ErrInvalidMintBlockTime       = errors.New("not mining time")
	ErrTakeItEasy                 = errors.New("take it easy")
	ErrNilBlockHeader             = errors.New("nil block header returned")

	//
	errInvalidSign     = errors.New("tx is not sign by valid validator")
	errMarshalError    = errors.New("marshal error")
	errNoValidProError = errors.New("no valid proposal")
	errApporvalError   = errors.New("approval can only use once in 3 epoch")
)

type Harmony struct {
	chainConfig *params.ChainConfig
	config      *params.HarmonyConfig // Consensus engine configuration parameters
	genesisHash common.Hash           //TODO(keep)
	db          ethdb.Database        // Database to store and retrieve snapshot checkpoints

	recents    *lru.ARCCache // Snapshots for recent block to speed up reorgs
	signatures *lru.ARCCache // Signatures of recent blocks to speed up mining

	ctx                  *Context
	signer               common.Address
	txSigner             types.Signer
	signFn               SignerFn
	confirmedBlockHeader *types.Header
	lock                 sync.RWMutex
	GlobalParams         types.GlobalParams

	// The fields below are for testing only
	fakeDiff bool // Skip difficulty verifications
}

func (h *Harmony) FinalizeAndAssemble(
	chain consensus.ChainHeaderReader,
	header *types.Header,
	state *state.StateDB,
	txs []*types.Transaction,
	uncles []*types.Header,
	receipts []*types.Receipt,
) (*types.Block, error) {
	h.Finalize(chain, header, state, txs, uncles)
	return types.NewBlock(header, txs, uncles, receipts, trie.NewStackTrie(nil)), nil
}

func (h *Harmony) SealHash(header *types.Header) common.Hash {
	return sigHash(header)
}

func (h *Harmony) Close() error {
	return nil
}

type SignerFn func(accounts.Account, string, []byte) ([]byte, error)

// NOTE: sigHash was copy from clique
// sigHash returns the hash which is used as input for the proof-of-authority
// signing. It is the hash of the entire header apart from the 65 byte signature
// contained at the end of the extra data.
//
// Note, the method requires the extra data to be at least 65 bytes, otherwise it
// panics. This is done to avoid accidentally using both forms (signature present
// or not), which could be abused to produce different hashes for the same header.
func sigHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()

	//rlp.Encode(hasher, []interface{}{
	//	header.ParentHash,
	//	header.UncleHash,
	//	header.Coinbase,
	//	header.EngineInfo, //@keep, 注意取blockhash的时候，直接取header.EngineInfo
	//	header.Root,
	//	header.TxHash,
	//	header.ReceiptHash,
	//	header.Bloom,
	//	header.Difficulty,
	//	header.Number,
	//	header.GasLimit,
	//	header.GasUsed,
	//	header.Time,
	//	header.Extra[:len(header.Extra)-65], // Yes, this will panic if extra is too short
	//	header.MixDigest,
	//	header.Nonce,
	//})

	enc := []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.EngineInfo, //@keep, 注意取blockhash的时候，直接取header.EngineInfo
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:len(header.Extra)-65], // Yes, this will panic if extra is too short
		header.MixDigest,
		header.Nonce,
	}

	if header.BaseFee != nil {
		enc = append(enc, header.BaseFee)
	}

	if err := rlp.Encode(hasher, enc); err != nil {
		panic("can't encode: " + err.Error())
	}

	hasher.Sum(hash[:0])
	return hash
}

func New(chainConfig *params.ChainConfig, db ethdb.Database) *Harmony {
	recents, _ := lru.NewARC(inmemorySnapshots)
	signatures, _ := lru.NewARC(inMemorySignatures)
	ctx, _ := NewEmptyContext(db)

	// get harmony config
	harmonyConfig := chainConfig.Harmony
	// Set any missing consensus parameters to their defaults
	if harmonyConfig != nil && harmonyConfig.Epoch == 0 {
		harmonyConfig.Epoch = epochLength
	}

	return &Harmony{
		chainConfig: chainConfig,
		config:      harmonyConfig,
		db:          db,
		ctx:         ctx,
		txSigner:    types.LatestSigner(chainConfig),
		signatures:  signatures,
		recents:     recents,
	}
}

// @keep, ok
func (h *Harmony) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

// @keep, ok
func (h *Harmony) Coinbase(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

func (h *Harmony) Ctx() *Context {
	return h.ctx
}

func (h *Harmony) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	return h.verifyHeader(chain, header, nil)
}

func (h *Harmony) verifyHeader(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	if header.Number == nil {
		return errUnknownBlock
	}
	number := header.Number.Uint64()
	// Unnecessary to verify the block from feature
	if header.Time > uint64(time.Now().Unix()) {
		return consensus.ErrFutureBlock
	}
	// Check that the extra-data contains both the vanity and signature
	if len(header.Extra) < extraVanity {
		return errMissingVanity
	}
	if len(header.Extra) < extraVanity+extraSeal {
		return errMissingSignature
	}

	// check extra data
	checkpoint := (number % h.config.Epoch) == 0

	// Ensure that the extra-data contains a signer list on checkpoint, but none otherwise
	signersBytes := len(header.Extra) - extraVanity - extraSeal
	if !checkpoint && signersBytes != 0 {
		//@keep，如果不是epoch,  signersBytes应该为0
		return errExtraValidators
	}

	if checkpoint && signersBytes%common.AddressLength != 0 {
		return errInvalidSpanValidators
	}

	// Ensure that the mix digest is zero as we don't have fork protection currently
	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}

	// Ensure that the block's difficulty is meaningful (may not be correct at this point)
	if number > 0 {
		if header.Difficulty == nil || (header.Difficulty.Cmp(diffInTurn) != 0 && header.Difficulty.Cmp(diffNoTurn) != 0) {
			return errInvalidDifficulty
		}
	}

	// Ensure that the block doesn't contain any uncles which are meaningless in harmony
	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
	}

	// Verify that the gas limit is <= 2^63-1
	if header.GasLimit > params.MaxGasLimit {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, params.MaxGasLimit)
	}

	// If all checks passed, validate any special fields for hard forks
	if err := misc.VerifyForkHashes(chain.Config(), header, false); err != nil {
		return err
	}

	//@keep, move to verifyCascadingFields
	//var parent *types.Header
	//if len(parents) > 0 {
	//	parent = parents[len(parents)-1]
	//} else {
	//	parent = chain.GetHeader(header.ParentHash, number-1)
	//}
	//if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
	//	return consensus.ErrUnknownAncestor
	//}
	//if parent.Time+blockInterval > header.Time+1 {
	//	return ErrInvalidTimestamp
	//}
	//return nil
	return h.verifyCascadingFields(chain, header, parents)
}

// verifyCascadingFields verifies all the header fields that are not standalone,
// rather depend on a batch of previous headers. The caller may optionally pass
// in a batch of parents (ascending order) to avoid looking those up from the
// database. This is useful for concurrently verifying a batch of new headers.
func (h *Harmony) verifyCascadingFields(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	// The genesis block is the always valid dead-end
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}

	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}

	// Verify that the gasUsed is <= gasLimit
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}

	//TODO(keep), build snapshot here
	snap, err := h.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}

	newSnap := snap.copy()
	//@keep,如果是epoch 块，
	//1.检查header中的signers和本地MPT中存的signers是否一致。
	//2.更新snap 中的signer，recents
	if number%h.config.Epoch == 0 {
		newValidators, err := h.GetLatestValidators(chain)
		if err != nil {
			return err
		}
		sort.Sort(signersAscending(newValidators))

		bz := make([]byte, len(newValidators)*common.AddressLength)

		for i, validator := range newValidators {
			copy(bz[i*common.AddressLength:], validator[:])
		}

		extraSuffix := len(header.Extra) - extraSeal
		if !bytes.Equal(header.Extra[extraVanity:extraSuffix], bz) {
			return errMismatchingCheckpointSigners
		}

		for validator, _ := range newSnap.Signers {
			delete(newSnap.Signers, validator)
		}
		for k, _ := range newSnap.Recents {
			delete(newSnap.Recents, k)
		}

		for _, validator := range newValidators {
			newSnap.Signers[validator] = struct{}{}
		}
	}

	//@keep，header.Time - parent.Time 必须要大于或者等于c.config.Period.
	err = h.verifyBlockTime(newSnap, header, parent)
	if err != nil {
		return err
	}

	if !chain.Config().IsLondon(header.Number) {
		// Verify BaseFee not present before EIP-1559 fork.
		if header.BaseFee != nil {
			return fmt.Errorf("invalid baseFee before fork: have %d, want <nil>", header.BaseFee)
		}
		if err := misc.VerifyGaslimit(parent.GasLimit, header.GasLimit); err != nil {
			return err
		}
	} else if err := misc.VerifyEip1559Header(chain.Config(), parent, header); err != nil {
		// Verify the header's EIP-1559 attributes.
		return err
	}

	return h.verifySeal(chain, header, parents)
}

// snapshot retrieves the authorization snapshot at a given point in time.
// @keep，获取指定hash的的snapshot
func (h *Harmony) snapshot(chain consensus.ChainHeaderReader, number uint64, hash common.Hash, parents []*types.Header) (*Snapshot, error) {
	// Search for a snapshot in memory or on disk for checkpoints
	var (
		headers []*types.Header
		snap    *Snapshot
	)
	for snap == nil {
		// If an in-memory snapshot was found, use that
		// 首先从recents 中找
		if s, ok := h.recents.Get(hash); ok {
			snap = s.(*Snapshot)
			break
		}
		// If an on-disk checkpoint snapshot can be found, use that
		if number%h.config.Epoch == 0 {
			//如果高度为checkpointInterval的整数倍，则直接尝试从数据库中读取Snapshot对象
			if s, err := loadSnapshot(h.config, h.signatures, h.db, hash); err == nil {
				log.Trace("Loaded snapshot from disk", "number", number, "hash", hash)
				snap = s
				break
			}
		}
		// If we're at the genesis , snapshot the initial state. Alternatively if we're
		// at a checkpoint block without a parent (light client CHT), or we have piled
		// up more headers than allowed to be reorged (chain reinit from a freezer),
		// consider the checkpoint trusted and snapshot it.
		//@keep,如果在创世块或者epoch块，直接从header中恢复出snapshot。
		if number == 0 || (number%h.config.Epoch == 0 /* && (len(headers) > params.FullImmutabilityThreshold || chain.GetHeaderByNumber(number-1) == nil)*/) {
			checkpoint := chain.GetHeaderByNumber(number)
			if checkpoint != nil {
				hash := checkpoint.Hash()

				//从checkpoint中取出signers列表
				signers := make([]common.Address, (len(checkpoint.Extra)-extraVanity-extraSeal)/common.AddressLength)
				for i := 0; i < len(signers); i++ {
					//copy出signer的列表
					copy(signers[i][:], checkpoint.Extra[extraVanity+i*common.AddressLength:])
				}
				//调用newSnapshot在checkpoint上创建Snapshot对象，并将其存入数据库中
				snap = newSnapshot(h.config, h.signatures, number, hash, signers)
				if err := snap.store(h.db); err != nil {
					return nil, err
				}
				log.Info("Stored checkpoint snapshot to disk", "number", number, "hash", hash)
				break
			}
		}
		// No snapshot for this header, gather the header and move backward
		//如果以上情况都不是，则往前回溯区块的链，并保存回溯过程中遇到的header
		var header *types.Header
		if len(parents) > 0 {
			// If we have explicit parents, pick from there (enforced)
			header = parents[len(parents)-1]
			if header.Hash() != hash || header.Number.Uint64() != number {
				return nil, consensus.ErrUnknownAncestor
			}
			parents = parents[:len(parents)-1]
		} else {
			// No explicit parents (or no more left), reach out to the database
			header = chain.GetHeader(hash, number)
			if header == nil {
				return nil, consensus.ErrUnknownAncestor
			}
		}
		//如果以上情况都不是，则往前回溯区块的链，并保存回溯过程中遇到的header。知道找到一个snapshot
		headers = append(headers, header)
		number, hash = number-1, header.ParentHash
	}
	// Previous snapshot found, apply any pending headers on top of it
	// @keep， 将headers 反转，反转后按高度从小到大排序
	for i := 0; i < len(headers)/2; i++ {
		headers[i], headers[len(headers)-1-i] = headers[len(headers)-1-i], headers[i]
	}
	//将回溯中遇到的headers传给apply方法，得到一个新的snap对象
	//@Keep，找到了之前的一个快照作为基准，然后将一路上遇到的headers 都传进去，构建一个较新的快照。
	snap, err := snap.apply(headers)
	if err != nil {
		return nil, err
	}

	h.recents.Add(snap.Hash, snap) //@keep，clique的recent和snapshot的recents各有一个recents，clique的recent就是一个LRU， snapshot中的recent记录了最近几个块的签名者。

	// If we've generated a new checkpoint snapshot, save to disk
	//@keep, len(headers) 说明这个epoch的snapshot 原来没有，是重建出来的，则将Snapshot对象存储到数据库中
	if snap.Number%h.config.Epoch == 0 && len(headers) > 0 {
		if err = snap.store(h.db); err != nil {
			return nil, err
		}
		log.Trace("Stored voting snapshot to disk", "number", snap.Number, "hash", snap.Hash)
	}
	return snap, err
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers. The
// method returns a quit channel to abort the operations and a results channel to
// retrieve the async verifications (the order is that of the input slice).
func (h *Harmony) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := h.verifyHeader(chain, header, headers[:i])
			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (h *Harmony) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

// VerifySeal implements consensus.Engine, checking whether the signature contained
// in the header satisfies the consensus protocol requirements.
func (h *Harmony) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	return h.verifySeal(chain, header, nil)
}

// verifySeal checks whether the signature contained in the header satisfies the
// consensus protocol requirements. The method accepts an optional list of parent
// headers that aren't yet part of the local blockchain to generate the snapshots
// from.
func (h *Harmony) verifySeal(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	// Verifying the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}

	// Retrieve the snapshot needed to verify this header and cache it
	snap, err := h.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}
	newSnap := snap.copy()
	//@keep,如果是epoch 块，
	//更新snap 中的signer，recents
	if number%h.config.Epoch == 0 {
		newValidators := make([]common.Address, (len(header.Extra)-extraVanity-extraSeal)/common.AddressLength)
		for i := 0; i < len(newValidators); i++ {
			//copy出signer的列表
			copy(newValidators[i][:], header.Extra[extraVanity+i*common.AddressLength:])
		}

		for validator, _ := range newSnap.Signers {
			delete(newSnap.Signers, validator)
		}

		for k, _ := range newSnap.Recents {
			delete(newSnap.Recents, k)
		}

		for _, validator := range newValidators {
			newSnap.Signers[validator] = struct{}{}
		}
	}

	// Resolve the authorization key and check against signers
	signer, err := ecrecover(header, h.signatures)
	if err != nil {
		return err
	}
	if signer != header.Coinbase {
		return errCoinBaseMisMatch
	}

	if _, ok := newSnap.Signers[signer]; !ok {
		return errUnauthorizedSigner
	}
	for seen, recent := range newSnap.Recents {
		if recent == signer {
			// Signer is among recents, only fail if the current block doesn't shift it out
			if limit := uint64(len(newSnap.Signers)/2 + 1); seen > number-limit {
				return errRecentlySigned
			}
		}
	}
	// Ensure that the difficulty corresponds to the turn-ness of the signer
	if !h.fakeDiff {
		inturn := newSnap.inturn(header.Number.Uint64(), signer)
		if inturn && header.Difficulty.Cmp(diffInTurn) != 0 {
			return errWrongDifficulty
		}
		if !inturn && header.Difficulty.Cmp(diffNoTurn) != 0 {
			return errWrongDifficulty
		}
	}

	return nil
}

// @keep, original verufySeal
//func (h *Harmony) verifySeal(chain consensus.ChainReader, header *types.Header, headers []*types.Header) error {
//	// Verifying the genesis block is not supported
//	number := header.Number.Uint64()
//	if number == 0 {
//		return errUnknownBlock
//	}
//	var prevHeader *types.Header
//	if len(headers) > 0 {
//		prevHeader = headers[len(headers)-1]
//	} else {
//		prevHeader = chain.GetHeader(header.ParentHash, number-1)
//	}
//	prevCtx, err := NewContextFromHash(h.ctx.EDB(), prevHeader.EngineInfo)
//	if err != nil {
//		return err
//	}
//	prevEpoch := &EpochContext{Context: prevCtx}
//	validator, err := prevEpoch.lookupValidator(header.Time)
//	if err != nil {
//		return err
//	}
//	if err := h.verifyBlockSigner(validator, header); err != nil {
//		return err
//	}
//	return h.updateConfirmedBlockHeader(chain)
//}

//func (h *Harmony) verifyBlockSigner(validator common.Address, header *types.Header) error {
//	signer, err := ecrecover(header, h.signatures)
//	if err != nil {
//		return err
//	}
//	if !bytes.Equal(signer.Bytes(), validator.Bytes()) {
//		return ErrInvalidBlockValidator
//	}
//	if !bytes.Equal(signer.Bytes(), header.Coinbase.Bytes()) {
//		return ErrMismatchSignerAndValidator
//	}
//	return nil
//}
//
//func (h *Harmony) updateConfirmedBlockHeader(chain consensus.ChainHeaderReader) error {
//	if h.confirmedBlockHeader == nil {
//		header, err := h.loadConfirmedBlockHeader(chain)
//		if err != nil {
//			header = chain.GetHeaderByNumber(0)
//			if header == nil {
//				return err
//			}
//		}
//		h.confirmedBlockHeader = header
//	}
//
//	curHeader := chain.CurrentHeader()
//	epoch := uint64(0)
//	validatorMap := make(map[common.Address]bool)
//	for h.confirmedBlockHeader.Hash() != curHeader.Hash() &&
//		h.confirmedBlockHeader.Number.Uint64() < curHeader.Number.Uint64() {
//		curEpoch := curHeader.Time / epochInterval
//		if curEpoch != epoch {
//			epoch = curEpoch
//			validatorMap = make(map[common.Address]bool)
//		}
//		// fast return
//		// if block number difference less consensusSize-witnessNum
//		// there is no need to check block is confirmed
//		if curHeader.Number.Int64()-h.confirmedBlockHeader.Number.Int64() < int64(consensusSize-len(validatorMap)) {
//			log.Debug(
//				"Harmony fast return",
//				"current", curHeader.Number.String(),
//				"confirmed", h.confirmedBlockHeader.Number.String(),
//				"witnessCount", len(validatorMap),
//			)
//			return nil
//		}
//		validatorMap[curHeader.Coinbase] = true
//		if len(validatorMap) >= consensusSize {
//			h.confirmedBlockHeader = curHeader
//			if err := h.storeConfirmedBlockHeader(h.db); err != nil {
//				return err
//			}
//			log.Debug("harmony set confirmed block header success", "currentHeader", curHeader.Number.String())
//			return nil
//		}
//		curHeader = chain.GetHeaderByHash(curHeader.ParentHash)
//		if curHeader == nil {
//			return ErrNilBlockHeader
//		}
//	}
//	return nil
//}
//
//func (h *Harmony) loadConfirmedBlockHeader(chain consensus.ChainHeaderReader) (*types.Header, error) {
//	key, err := h.db.Get(confirmedBlockHead)
//	if err != nil {
//		return nil, err
//	}
//	header := chain.GetHeaderByHash(common.BytesToHash(key))
//	if header == nil {
//		return nil, ErrNilBlockHeader
//	}
//	return header, nil
//}

//// store inserts the snapshot into the database.
//func (h *Harmony) storeConfirmedBlockHeader(db ethdb.Database) error {
//	return db.Put(confirmedBlockHead, h.confirmedBlockHeader.Hash().Bytes())
//}

func (h *Harmony) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	header.Coinbase = h.signer
	header.Nonce = types.BlockNonce{}
	number := header.Number.Uint64()

	//@keep， 因为snap 取得是前一个块的snap，所以在calcDifficulty时要将snap.Number+1
	snap, err := h.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}

	if len(header.Extra) < extraVanity {
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, extraVanity-len(header.Extra))...)
	}
	header.Extra = header.Extra[:extraVanity]

	//@keep，准备出epoch块，将本地的signers添加到header.extra，并基于新snap计算difficulty and blockTime
	newSnap := snap.copy()
	if number%h.config.Epoch == 0 {
		for validator, _ := range newSnap.Signers {
			delete(newSnap.Signers, validator)
		}
		for k, _ := range newSnap.Recents {
			delete(newSnap.Recents, k)
		}

		newValidators, err := h.GetLatestValidators(chain)
		if err != nil {
			return err
		}
		sort.Sort(signersAscending(newValidators))

		for _, validator := range newValidators {
			newSnap.Signers[validator] = struct{}{}
			header.Extra = append(header.Extra, validator.Bytes()...)
		}
	}

	header.Extra = append(header.Extra, make([]byte, extraSeal)...)
	// Mix digest is reserved for now, set to empty
	header.MixDigest = common.Hash{}

	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}

	//@keep, 基于新newSnap计算difficulty and blockTime
	header.Difficulty = calcDifficulty(newSnap, h.signer)
	header.Time = h.blockTime(newSnap, parent)
	if header.Time < uint64(time.Now().Unix()) {
		header.Time = uint64(time.Now().Unix())
	}
	return nil
}

func AccumulateRewards(config *params.ChainConfig, state *state.StateDB, header *types.Header, uncles []*types.Header, rewards *big.Int) {
	// Select the correct block reward based on chain progression
	state.AddBalance(header.Coinbase, rewards)
}

func (h *Harmony) GetDB() ethdb.Database {
	return h.db
}
func (h *Harmony) Finalize(
	chain consensus.ChainHeaderReader,
	header *types.Header,
	state *state.StateDB,
	txs []*types.Transaction,
	uncles []*types.Header,
) {
	s := types.GlobalParams{}
	g := rawdb.ReadParams(h.db)

	err := json.Unmarshal(g, &s)
	if err != nil {
		log.Error("Unmarshal,", "err", err)
	}

	// Accumulate block rewards and commit the final state root
	AccumulateRewards(chain.Config(), state, header, uncles, s.FrontierBlockReward)
	parent := chain.GetHeaderByHash(header.ParentHash)
	epochContext := &EpochContext{
		stateDB:   state,
		Context:   h.ctx,
		TimeStamp: header.Time,
	}
	if timeOfFirstBlock == 0 {
		if firstBlockHeader := chain.GetHeaderByNumber(1); firstBlockHeader != nil {
			timeOfFirstBlock = firstBlockHeader.Time
		}
	}

	genesis := chain.GetHeaderByNumber(0)
	err = epochContext.tryElect(genesis, parent, h)

	if err != nil {
		log.Error("got error when elect next epoch,", "err", err)
	}

	// apply vote txs here, these tx is no reason to fail, no err no revert needed
	h.applyVoteTxs(txs)
	// apply proposal txs here,these tx is no reason to fail, no err no revert needed
	err = h.applyProposalTx(txs, header, chain.Config())
	if err != nil {
		log.Error("applyProposalTx error", "err", err)
	}
	// update mint count trie
	updateMintCnt(parent.Time, header.Time, header.Coinbase, h.ctx)
	if header.EngineInfo, err = h.ctx.Commit(); err != nil {
		log.Error("engine context commit", "err", err)
	}
	header.Root, err = state.Commit(true)
	if err != nil {
		log.Error("block commit", "err", err)
	}
	log.Debug(
		"current Hashes",
		"bn", header.Number,
		"engine", header.EngineInfo.String(),
		"root", header.Root.String())
}

func (h *Harmony) applyProposalTx(txs []*types.Transaction, header *types.Header, config *params.ChainConfig) error {
	var err error
	for _, tx := range txs {
		if tx.Type() >= types.ProposalTxType && tx.Type() <= types.ApproveProposalTxType {
			err = h.ApplyProposalTx(tx, header, config)
		}
	}
	return err
}

func in(target common.Address, str_array []common.Address) bool {
	for _, element := range str_array {
		if target == element {
			return true
		}
	}
	return false
}

func (h *Harmony) ApplyProposalTx(tx *types.Transaction, header *types.Header, config *params.ChainConfig) error {
	if tx.Type() == types.ProposalTxType { // 提案交易
		// 取出全局参数
		globalParams, err := getParams(h)

		if err != nil {
			return err
		}
		if globalParams.HashMap[tx.Hash()] != "" { // 说明交易本次已经处理过，是二次广播来的交易
			return nil
		}
		log.Info("got ProposalTxType")
		len := len(globalParams.ValidProposals) + len(globalParams.InValidProposals)
		id := fmt.Sprintf("%s.%d", params.Version, len)
		globalParams.ValidProposals[id] = tx.Hash()
		globalParams.HashMap[tx.Hash()] = id // 表示已经被处理，这里要提出第二次广播又进来的交易

		globalParams.ProposalEpoch[id] = header.Number.Uint64() / h.config.Epoch // /当前的epoch

		data, err := json.Marshal(globalParams)
		if err != nil {
			return errMarshalError
		}
		// 写回rawdb
		rawdb.WriteParams(h.GetDB(), globalParamsKey, data)
	}
	if tx.Type() == types.ApproveProposalTxType { // 表决交易--仅仅将授权放入，具体处理在选举中
		// 取出全局参数
		globalParams, err := getParams(h)
		if err != nil {
			return err
		}

		validators, _ := h.Ctx().GetValidators()
		id := string(tx.Data())

		if _, ok := globalParams.ValidProposals[id]; ok { // 存在有效提案
			curEpoch := header.Number.Uint64() / h.config.Epoch // 查看当前id是否过期
			validCnt := globalParams.ProposalValidEpochCnt

			if curEpoch <= globalParams.ProposalEpoch[id]+validCnt {
				// 找到tx的from地址
				msg, err := tx.AsMessage(types.MakeSigner(config, header.Number), header.BaseFee)
				if err != nil {
					return err
				}

				result := in(msg.From(), validators) // 交易的from是否是验证者地址
				if result == false {
					return errInvalidSign
				}
				// 限制授权地址的使用，先从ApproveMap找到msg.From()
				if _, ok := globalParams.ApproveMap[msg.From().String()]; ok {
					lastApprovalEpoch := globalParams.ApproveMap[msg.From().String()]
					if curEpoch > lastApprovalEpoch+3 { // 在判断离上次授权是否经过了3个epoch
						globalParams.ProposalApproves[id] = append(globalParams.ProposalApproves[id], msg.From())
						globalParams.ApproveMap[msg.From().String()] = curEpoch
					} else {
						return errApporvalError
					}
				} else { // 不存在-直接授权
					globalParams.ProposalApproves[id] = append(globalParams.ProposalApproves[id], msg.From())
					globalParams.ApproveMap[msg.From().String()] = curEpoch
				}
			}
		} else { // 没有有效交易
			return errNoValidProError
		}
		data, err := json.Marshal(globalParams)
		if err != nil {
			return errMarshalError
		}

		// 写回rawdb
		rawdb.WriteParams(h.GetDB(), globalParamsKey, data)
	}
	return nil
}

func (h *Harmony) applyVoteTxs(txs []*types.Transaction) {
	for _, tx := range txs {
		if tx.Type() >= types.CandidateTxType && tx.Type() <= types.UnDelegateTxType {
			_ = h.ApplyVoteTx(tx)
		}
	}
}

func (h *Harmony) ApplyVoteTx(tx *types.Transaction) error {
	from, err := types.Sender(h.txSigner, tx)
	if err != nil {
		log.Warn("get sender", "err", err)
	}
	switch tx.Type() {
	case types.CandidateTxType:
		if err = h.Ctx().BecomeCandidate(from); err != nil {
			log.Warn("become candidate", "err", err)
			return err
		}
	case types.UnCandidateTxType:
		if err = h.Ctx().KickOutCandidate(from); err != nil {
			log.Warn("leave candidate", "err", err)
			return err
		}
	case types.DelegateTxType:
		if err = h.Ctx().Delegate(from, *tx.To()); err != nil {
			log.Warn("delegating", "err", err)
			return err
		}
	case types.UnDelegateTxType:
		if err = h.Ctx().UnDelegate(from, *tx.To()); err != nil {
			log.Warn("leave delegating", "err", err)
			return err
		}
	}
	return nil
}

//func (h *Harmony) checkDeadline(lastBlock *types.Block, now uint64) error {
//	prevSlotTime := prevSlot(now)
//	nextSlotTime := nextSlot(now)
//	log.Trace("checkDeadLine", "lastBlock", lastBlock.Time(), "now", now, "prev", prevSlotTime, "next", nextSlotTime)
//	if lastBlock.Time() >= nextSlotTime {
//		return ErrMintFutureBlock
//	}
//	// last block was arrived, or time's up
//	if lastBlock.Time() == prevSlotTime || nextSlotTime-now <= 1 {
//		return nil
//	}
//	return ErrWaitForPrevBlock
//}
//
//func (h *Harmony) CheckValidator(lastBlock *types.Block, now uint64) error {
//	if err := h.checkDeadline(lastBlock, now); err != nil {
//		return err
//	}
//	lastCtx, err := NewContextFromHash(h.ctx.EDB(), lastBlock.Header().EngineInfo)
//	if err != nil {
//		return err
//	}
//	lastEpochContext := &EpochContext{Context: lastCtx}
//	validator, err := lastEpochContext.lookupValidator(now)
//	if err != nil {
//		return err
//	}
//	if (validator == common.Address{}) || !bytes.Equal(validator.Bytes(), h.signer.Bytes()) {
//		return ErrInvalidBlockValidator
//	}
//	if now-lastBlock.Time() < (h.config.Period+1)/2 {
//		return ErrTakeItEasy
//	}
//	return nil
//}

// Seal generates a new block for the given input block with the local miner's
// seal place on top.
func (h *Harmony) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	number := block.Header().Number.Uint64()
	// Sealing the genesis block is not supported
	if number == 0 {
		return errUnknownBlock
	}

	// time's up, sign the block
	sealHash, err := h.signFn(accounts.Account{Address: h.signer}, "", sigHash(block.Header()).Bytes())
	if err != nil {
		log.Error("signFn error", "err", err)
		return nil
	}
	copy(block.Header().Extra[len(block.Header().Extra)-extraSeal:], sealHash)

	go func() {
		select {
		case <-stop:
			return
		case results <- block.WithSeal(block.Header()):
			log.Warn("engine Sealed block broadcasting...", "bn", block.NumberU64(), "t", uint64(time.Now().Unix())-block.Time())
			return
		default:
			log.Warn("Sealing result is not read by miner", "sealHash", sealHash)
		}
	}()

	return nil
}

// @keep, 此函数有些问题，如果epoch-1的块，需要最新的validator list 才能计算难度
func (h *Harmony) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	snap, err := h.snapshot(chain, parent.Number.Uint64(), parent.Hash(), nil)
	if err != nil {
		return nil
	}
	h.lock.RLock()
	signer := h.signer
	h.lock.RUnlock()

	//TODO(keep), 如果parent是上一个epoch 的最后一个块,
	newSnap := snap.copy()
	epochNumber := parent.Number.Uint64() / h.config.Epoch
	if parent.Number.Uint64()%h.config.Epoch == h.config.Epoch-1 {
		epochNumber += 1
	}

	validators, err := h.GetValidatorsInEpoch(chain, epochNumber)
	if err != nil {
		panic("CalcDifficulty, fail to get epoch's validators")
	}

	for validator, _ := range newSnap.Signers {
		delete(newSnap.Signers, validator)
	}

	for _, validator := range validators {
		newSnap.Signers[validator] = struct{}{}
	}

	return calcDifficulty(newSnap, signer)
}

func (h *Harmony) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return []rpc.API{{
		Namespace: "harmony",
		Version:   "1.0",
		Service:   &API{chain: chain, engine: h},
		Public:    true,
	}}
}

func (h *Harmony) Authorize(signer common.Address, signFn SignerFn) {
	h.lock.Lock()
	h.signer = signer
	h.signFn = signFn
	h.lock.Unlock()
}

// ecRecover extracts the Ethereum account address from a signed header.
func ecrecover(header *types.Header, sigCache *lru.ARCCache) (common.Address, error) {
	// If the signature's already cached, return that
	hash := header.Hash()
	if address, known := sigCache.Get(hash); known {
		return address.(common.Address), nil
	}
	// Retrieve the signature from the header extra-data
	if len(header.Extra) < extraSeal {
		return common.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-extraSeal:]
	// Recover the public key and the Ethereum address
	pubKey, err := crypto.Ecrecover(sigHash(header).Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubKey[1:])[12:])
	sigCache.Add(hash, signer)
	return signer, nil
}

//func prevSlot(now uint64) uint64 {
//	return (now - 1) / blockInterval * blockInterval
//}
//
//func nextSlot(now uint64) uint64 {
//	return (now + blockInterval - 1) / blockInterval * blockInterval
//}

// update counts in MintCntTrie for the miner of newBlock
func updateMintCnt(parentBlockTime, currentBlockTime uint64, validator common.Address, ctx *Context) {
	//currentEpoch := parentBlockTime / epochInterval
	//currentEpochBytes := make([]byte, 8)
	//binary.BigEndian.PutUint64(currentEpochBytes, currentEpoch)
	//
	//cnt := uint64(1)
	//newEpoch := currentBlockTime / epochInterval
	//// still during the currentEpochID
	//if currentEpoch == newEpoch {
	//	iter := ctx.mintCntTrie.Iterator(currentEpochBytes)
	//
	//	// when current is not genesis, read last count from the MintCntTrie
	//	if iter.Next() {
	//		cntBytes, err := ctx.mintCntTrie.t.TryGet(append(currentEpochBytes, validator.Bytes()...))
	//		if err != nil {
	//			return
	//		}
	//		// not the first time to mint
	//		if cntBytes != nil {
	//			cnt = binary.BigEndian.Uint64(cntBytes) + 1
	//		}
	//	}
	//}
	//
	//newCntBytes := make([]byte, 8)
	//newEpochBytes := make([]byte, 8)
	//binary.BigEndian.PutUint64(newEpochBytes, newEpoch)
	//binary.BigEndian.PutUint64(newCntBytes, cnt)
	//ctx.mintCntTrie.t.Update(append(newEpochBytes, validator.Bytes()...), newCntBytes)
}

// TODO(keep), validators
func (h *Harmony) GetLatestValidators(chain consensus.ChainHeaderReader) ([]common.Address, error) {
	header := chain.CurrentHeader()
	epohTrie, err := newEpochTrie(header.EngineInfo.EpochHash, h.db)
	if err != nil {
		return nil, err
	}
	ctx := Context{}
	ctx.SetEpochTrie(epohTrie)
	validators, err := ctx.GetValidators()
	if err != nil {
		return nil, err
	}
	return validators, nil
}

func (h *Harmony) GetValidatorsInEpoch(chain consensus.ChainHeaderReader, epochNumber uint64) ([]common.Address, error) {
	header := chain.CurrentHeader()
	epohTrie, err := newEpochTrie(header.EngineInfo.EpochHash, h.db)
	if err != nil {
		return nil, err
	}
	ctx := Context{}
	ctx.SetEpochTrie(epohTrie)
	validators, err := ctx.GetValidatorsInEpoch(epochNumber)
	if err != nil {
		return nil, err
	}

	sort.Sort(signersAscending(validators))
	return validators, nil
}

func calcDifficulty(snap *Snapshot, validator common.Address) *big.Int {
	if snap.inturn(snap.Number+1, validator) {
		return new(big.Int).Set(diffInTurn)
	}
	return new(big.Int).Set(diffNoTurn)
}

// SealHash returns the hash of a block prior to it being sealed.
func SealHash(header *types.Header) (hash common.Hash) {
	return sigHash(header)
}
