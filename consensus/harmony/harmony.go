package harmony

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
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
	extraVanity        = 32   // Fixed number of extra-data prefix bytes reserved for signer vanity
	extraSeal          = 65   // Fixed number of extra-data suffix bytes reserved for signer seal
	inMemorySignatures = 4096 // Number of recent block signatures to keep in memory

	blockInterval    = uint64(2)
	epochInterval    = uint64(600)
	maxValidatorSize = 1
	safeSize         = maxValidatorSize*2/3 + 1
	consensusSize    = maxValidatorSize*2/3 + 1
)

var (
	defaultDifficulty = common.Big1 // The default block defaultDifficulty in the harmony consensus

	frontierBlockReward = big.NewInt(5e+18) // Block reward in wei for successfully mining a block

	timeOfFirstBlock = uint64(0)

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
	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")
	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash  = errors.New("non empty uncle hash")
	errInvalidDifficulty = errors.New("invalid defaultDifficulty")

	// ErrInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp + the minimum block period.
	ErrInvalidTimestamp           = errors.New("invalid timestamp")
	ErrWaitForPrevBlock           = errors.New("wait for last block arrived")
	ErrMintFutureBlock            = errors.New("mint the future block")
	ErrMismatchSignerAndValidator = errors.New("mismatch block signer and validator")
	ErrInvalidBlockValidator      = errors.New("not my turn")
	ErrInvalidMintBlockTime       = errors.New("not mining time")
	ErrNilBlockHeader             = errors.New("nil block header returned")
)
var (
	uncleHash = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.
)

type Harmony struct {
	config *params.HarmonyConfig // Consensus engine configuration parameters
	db     ethdb.Database        // Database to store and retrieve snapshot checkpoints

	ctx                  *Context
	signatures           *lru.ARCCache // Signatures of recent blocks to speed up mining
	signer               common.Address
	txSigner             types.Signer
	signFn               SignerFn
	confirmedBlockHeader *types.Header
	mu                   sync.RWMutex
	stop                 chan bool
	GlobalParams         types.GlobalParams
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

	rlp.Encode(hasher, []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.EngineInfo,
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
	})
	hasher.Sum(hash[:0])
	return hash
}

func New(config *params.ChainConfig, engineDB ethdb.Database) *Harmony {
	signatures, _ := lru.NewARC(inMemorySignatures)
	ctx, _ := NewEmptyContext(engineDB)

	var h Harmony
	h.config = config.Harmony
	h.db = engineDB
	h.ctx = ctx
	h.txSigner = types.LatestSigner(config)
	h.signatures = signatures
	h.GlobalParams.Init()
	return &h
}

func (h *Harmony) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

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
	// Ensure that the mix digest is zero as we don't have fork protection currently
	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}
	// Difficulty always 1
	if defaultDifficulty.Cmp(header.Difficulty) != 0 {
		return errInvalidDifficulty
	}
	// Ensure that the block doesn't contain any uncles which are meaningless in harmony
	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
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
	if parent.Time+blockInterval > header.Time {
		return ErrInvalidTimestamp
	}
	return nil
}

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

func (h *Harmony) verifySeal(chain consensus.ChainReader, header *types.Header, headers []*types.Header) error {
	// Verifying the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}
	var prevHeader *types.Header
	if len(headers) > 0 {
		prevHeader = headers[len(headers)-1]
	} else {
		prevHeader = chain.GetHeader(header.ParentHash, number-1)
	}
	prevCtx, err := NewContextFromHash(h.ctx.EDB(), prevHeader.EngineInfo)
	if err != nil {
		return err
	}
	prevEpoch := &EpochContext{Context: prevCtx}
	validator, err := prevEpoch.lookupValidator(header.Time)
	if err != nil {
		return err
	}
	if err := h.verifyBlockSigner(validator, header); err != nil {
		return err
	}
	return h.updateConfirmedBlockHeader(chain)
}

func (h *Harmony) verifyBlockSigner(validator common.Address, header *types.Header) error {
	signer, err := ecRecover(header, h.signatures)
	if err != nil {
		return err
	}
	if bytes.Compare(signer.Bytes(), validator.Bytes()) != 0 {
		return ErrInvalidBlockValidator
	}
	if bytes.Compare(signer.Bytes(), header.Coinbase.Bytes()) != 0 {
		return ErrMismatchSignerAndValidator
	}
	return nil
}

func (h *Harmony) updateConfirmedBlockHeader(chain consensus.ChainHeaderReader) error {
	if h.confirmedBlockHeader == nil {
		header, err := h.loadConfirmedBlockHeader(chain)
		if err != nil {
			header = chain.GetHeaderByNumber(0)
			if header == nil {
				return err
			}
		}
		h.confirmedBlockHeader = header
	}

	curHeader := chain.CurrentHeader()
	epoch := uint64(0)
	validatorMap := make(map[common.Address]bool)
	for h.confirmedBlockHeader.Hash() != curHeader.Hash() &&
		h.confirmedBlockHeader.Number.Uint64() < curHeader.Number.Uint64() {
		curEpoch := curHeader.Time / epochInterval
		if curEpoch != epoch {
			epoch = curEpoch
			validatorMap = make(map[common.Address]bool)
		}
		// fast return
		// if block number difference less consensusSize-witnessNum
		// there is no need to check block is confirmed
		if curHeader.Number.Int64()-h.confirmedBlockHeader.Number.Int64() < int64(consensusSize-len(validatorMap)) {
			log.Debug(
				"Harmony fast return",
				"current", curHeader.Number.String(),
				"confirmed", h.confirmedBlockHeader.Number.String(),
				"witnessCount", len(validatorMap),
			)
			return nil
		}
		validatorMap[curHeader.Coinbase] = true
		if len(validatorMap) >= consensusSize {
			h.confirmedBlockHeader = curHeader
			if err := h.storeConfirmedBlockHeader(h.db); err != nil {
				return err
			}
			log.Debug("harmony set confirmed block header success", "currentHeader", curHeader.Number.String())
			return nil
		}
		curHeader = chain.GetHeaderByHash(curHeader.ParentHash)
		if curHeader == nil {
			return ErrNilBlockHeader
		}
	}
	return nil
}

func (h *Harmony) loadConfirmedBlockHeader(chain consensus.ChainHeaderReader) (*types.Header, error) {
	key, err := h.db.Get(confirmedBlockHead)
	if err != nil {
		return nil, err
	}
	header := chain.GetHeaderByHash(common.BytesToHash(key))
	if header == nil {
		return nil, ErrNilBlockHeader
	}
	return header, nil
}

// store inserts the snapshot into the database.
func (h *Harmony) storeConfirmedBlockHeader(db ethdb.Database) error {
	return db.Put(confirmedBlockHead, h.confirmedBlockHeader.Hash().Bytes())
}

func (h *Harmony) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	header.Nonce = types.BlockNonce{}
	number := header.Number.Uint64()
	if len(header.Extra) < extraVanity {
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, extraVanity-len(header.Extra))...)
	}
	header.Extra = header.Extra[:extraVanity]
	header.Extra = append(header.Extra, make([]byte, extraSeal)...)
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	header.Difficulty = defaultDifficulty
	header.Coinbase = h.signer
	return nil
}

func AccumulateRewards(config *params.ChainConfig, state *state.StateDB, header *types.Header, uncles []*types.Header, rewards *big.Int) {
	// Select the correct block reward based on chain progression
	var blockRewards big.Int
	if rewards.Uint64() > 0 {
		blockRewards = *rewards
	} else {
		blockRewards = *frontierBlockReward
	}
	state.AddBalance(header.Coinbase, &blockRewards)
}

func (h *Harmony) Finalize(
	chain consensus.ChainHeaderReader,
	header *types.Header,
	state *state.StateDB,
	txs []*types.Transaction,
	uncles []*types.Header,
) {
	// Accumulate block rewards and commit the final state root
	AccumulateRewards(chain.Config(), state, header, uncles, h.GlobalParams.GetRewards())

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

	err := epochContext.tryElect(genesis, parent)
	if err != nil {
		log.Error("got error when elect next epoch,", "err", err)
	}

	// apply vote txs here, these tx is no reason to fail, no err no revert needed
	h.applyVoteTxs(txs)

	//update mint count trie
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

func (h *Harmony) applyVoteTxs(txs []*types.Transaction) {
	for _, tx := range txs {
		if tx.Type() >= types.CandidateTxType && tx.Type() <= types.UnDelegateTxType {
			from, err := types.Sender(h.txSigner, tx)
			if err != nil {
				log.Warn("get sender", "err", err)
			}
			switch tx.Type() {
			case types.CandidateTxType:
				if err = h.Ctx().BecomeCandidate(from); err != nil {
					log.Warn("become candidate", "err", err)
				}
			case types.UnCandidateTxType:
				if err = h.Ctx().KickOutCandidate(from); err != nil {
					log.Warn("leave candidate", "err", err)
				}
			case types.DelegateTxType:
				if err = h.Ctx().Delegate(from, *tx.To()); err != nil {
					log.Warn("delegating", "err", err)
				}
			case types.UnDelegateTxType:
				if err = h.Ctx().UnDelegate(from, *tx.To()); err != nil {
					log.Warn("leave delegating", "err", err)
				}
			}
		}
	}
}

func (h *Harmony) checkDeadline(lastBlock *types.Block, now uint64) error {
	prevSlotTime := prevSlot(now)
	nextSlotTime := nextSlot(now)
	log.Debug("checkDeadLine", "lastBlock", lastBlock.Time(), "now", now, "prev", prevSlotTime, "next", nextSlotTime)
	if lastBlock.Time() >= nextSlotTime {
		return ErrMintFutureBlock
	}
	// last block was arrived, or time's up
	if lastBlock.Time() == prevSlotTime || nextSlotTime-now <= 1 {
		return nil
	}
	return ErrWaitForPrevBlock
}

func (h *Harmony) CheckValidator(lastBlock *types.Block, now uint64) error {
	if err := h.checkDeadline(lastBlock, now); err != nil {
		return err
	}
	lastCtx, err := NewContextFromHash(h.ctx.EDB(), lastBlock.Header().EngineInfo)
	if err != nil {
		return err
	}
	lastEpochContext := &EpochContext{Context: lastCtx}
	validator, err := lastEpochContext.lookupValidator(now)
	if err != nil {
		return err
	}
	if (validator == common.Address{}) || bytes.Compare(validator.Bytes(), h.signer.Bytes()) != 0 {
		return ErrInvalidBlockValidator
	}
	return nil
}

// Seal generates a new block for the given input block with the local miner's
// seal place on top.
func (h *Harmony) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	number := block.Header().Number.Uint64()
	// Sealing the genesis block is not supported
	if number == 0 {
		return errUnknownBlock
	}
	now := uint64(time.Now().Unix())
	delay := nextSlot(now) - now

	block.Header().Time = uint64(time.Now().Unix())
	// time's up, sign the block
	sealHash, err := h.signFn(accounts.Account{Address: h.signer}, "", sigHash(block.Header()).Bytes())
	if err != nil {
		log.Error("signFn error", "err", err)
		return nil
	}
	copy(block.Header().Extra[len(block.Header().Extra)-extraSeal:], sealHash)

	// Wait until sealing is terminated or delay timeout.
	log.Trace("Waiting for slot to sign and propagate", "delay", common.PrettyDuration(delay))
	go func() {
		select {
		case <-stop:
			return
		case <-time.After(time.Duration(delay) * time.Second):
		}

		select {
		case results <- block.WithSeal(block.Header()):
		default:
			log.Warn("Sealing result is not read by miner", "sealHash", sealHash)
		}
	}()

	return nil
}

func (h *Harmony) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	return defaultDifficulty
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
	h.mu.Lock()
	h.signer = signer
	h.signFn = signFn
	h.mu.Unlock()
}

// ecRecover extracts the Ethereum account address from a signed header.
func ecRecover(header *types.Header, sigCache *lru.ARCCache) (common.Address, error) {
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

func prevSlot(now uint64) uint64 {
	return (now - 1) / blockInterval * blockInterval
}

func nextSlot(now uint64) uint64 {
	return (now + blockInterval - 1) / blockInterval * blockInterval
}

// update counts in MintCntTrie for the miner of newBlock
func updateMintCnt(parentBlockTime, currentBlockTime uint64, validator common.Address, ctx *Context) {
	currentEpoch := parentBlockTime / epochInterval
	currentEpochBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(currentEpochBytes, currentEpoch)

	cnt := uint64(1)
	newEpoch := currentBlockTime / epochInterval
	// still during the currentEpochID
	if currentEpoch == newEpoch {
		iter := ctx.mintCntTrie.Iterator(currentEpochBytes)

		// when current is not genesis, read last count from the MintCntTrie
		if iter.Next() {
			cntBytes, err := ctx.mintCntTrie.t.TryGet(append(currentEpochBytes, validator.Bytes()...))
			if err != nil {
				return
			}
			// not the first time to mint
			if cntBytes != nil {
				cnt = binary.BigEndian.Uint64(cntBytes) + 1
			}
		}
	}

	newCntBytes := make([]byte, 8)
	newEpochBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(newEpochBytes, newEpoch)
	binary.BigEndian.PutUint64(newCntBytes, cnt)
	ctx.mintCntTrie.t.Update(append(newEpochBytes, validator.Bytes()...), newCntBytes)
}
