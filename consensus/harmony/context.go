package harmony

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"golang.org/x/crypto/sha3"
)

var ErrDelegateInvalid = errors.New("delegatorAddr is in validators and invalid,please unstake first")

type Trie struct {
	t *trie.Trie
	d *trie.Database
}

func (t *Trie) Copy() *Trie {
	return &Trie{
		t: t.t.Copy(),
		d: trie.NewDatabase(t.d.DiskDB()),
	}
}

func (t *Trie) Hash() common.Hash {
	return t.t.Hash()
}

func (t *Trie) Iterator(k []byte) *trie.Iterator {
	if k == nil {
		return trie.NewIterator(t.t.NodeIterator(nil))
	} else {
		return trie.NewIterator(t.t.PrefixIterator(k))
	}
}

func (t *Trie) TryUpdate(k, v []byte) error {
	return t.t.TryUpdate(k, v)
}

type Context struct {
	epochTrie     *Trie
	candidateTrie *Trie
	delegateTrie  *Trie
	voteTrie      *Trie
	mintCntTrie   *Trie
}

var (
	ownerEpoch     = common.BytesToHash([]byte("epoch"))
	ownerCandidate = common.BytesToHash([]byte("candidate"))
	ownerDelegate  = common.BytesToHash([]byte("delegate"))
	ownerVote      = common.BytesToHash([]byte("vote"))
	ownerMint      = common.BytesToHash([]byte("mint"))
)

func NewTrie(root common.Hash, tdb *trie.Database) (*trie.Trie, error) {
	return trie.New(common.Hash{}, root, tdb)
}

func newTrie(owner, root common.Hash, edb ethdb.KeyValueStore) (*Trie, error) {
	d := trie.NewDatabase(edb)
	if t, err := trie.New(owner, root, d); err != nil {
		return nil, err
	} else {
		return &Trie{
			t: t,
			d: d,
		}, nil
	}
}

func newEpochTrie(root common.Hash, edb ethdb.KeyValueStore) (*Trie, error) {
	return newTrie(ownerEpoch, root, edb)
}

func newCandidateTrie(root common.Hash, edb ethdb.KeyValueStore) (*Trie, error) {
	return newTrie(ownerCandidate, root, edb)
}

func newDelegateTrie(root common.Hash, edb ethdb.KeyValueStore) (*Trie, error) {
	return newTrie(ownerDelegate, root, edb)
}

func newVoteTrie(root common.Hash, edb ethdb.KeyValueStore) (*Trie, error) {
	return newTrie(ownerVote, root, edb)
}

// 暴露给接口使用
func NewVoteTrie(root common.Hash, edb ethdb.KeyValueStore) (*Trie, error) {
	return newTrie(ownerVote, root, edb)
}

func newMintTrie(root common.Hash, edb ethdb.KeyValueStore) (*Trie, error) {
	return newTrie(ownerMint, root, edb)
}

func NewEmptyContext(edb ethdb.KeyValueStore) (*Context, error) {
	return NewContextFromHash(edb, types.EmptyEngineInfo)
}

func NewContextFromHash(edb ethdb.KeyValueStore, info types.EngineInfo) (*Context, error) {
	epoch, err := newEpochTrie(info.EpochHash, edb)
	if err != nil {
		return nil, err
	}
	candidate, err := newCandidateTrie(info.CandidateHash, edb)
	if err != nil {
		return nil, err
	}
	delegate, err := newDelegateTrie(info.DelegateHash, edb)
	if err != nil {
		return nil, err
	}
	vote, err := newVoteTrie(info.VoteHash, edb)
	if err != nil {
		return nil, err
	}
	mint, err := newMintTrie(info.MintCntHash, edb)
	if err != nil {
		return nil, err
	}
	return &Context{
		epochTrie:     epoch,
		candidateTrie: candidate,
		delegateTrie:  delegate,
		voteTrie:      vote,
		mintCntTrie:   mint,
	}, nil
}

func (c *Context) Copy() *Context {
	return &Context{
		epochTrie:     c.epochTrie.Copy(),
		candidateTrie: c.candidateTrie.Copy(),
		delegateTrie:  c.delegateTrie.Copy(),
		voteTrie:      c.voteTrie.Copy(),
		mintCntTrie:   c.mintCntTrie.Copy(),
	}
}

func (c *Context) Root() (h common.Hash) {
	hw := sha3.NewLegacyKeccak256()
	_ = rlp.Encode(hw, c.epochTrie.Hash())
	_ = rlp.Encode(hw, c.candidateTrie.Hash())
	_ = rlp.Encode(hw, c.delegateTrie.Hash())
	_ = rlp.Encode(hw, c.voteTrie.Hash())
	_ = rlp.Encode(hw, c.mintCntTrie.Hash())
	hw.Sum(h[:0])
	return h
}

func (c *Context) Info() types.EngineInfo {
	return types.EngineInfo{
		EpochHash:     c.epochTrie.Hash(),
		CandidateHash: c.candidateTrie.Hash(),
		DelegateHash:  c.delegateTrie.Hash(),
		VoteHash:      c.voteTrie.Hash(),
		MintCntHash:   c.mintCntTrie.Hash(),
	}
}

func (c *Context) Snapshot() *Context {
	return c.Copy()
}

func (c *Context) RevertToSnapShot(snapshot *Context) {
	c.epochTrie = snapshot.epochTrie
	c.candidateTrie = snapshot.candidateTrie
	c.delegateTrie = snapshot.delegateTrie
	c.voteTrie = snapshot.voteTrie
	c.mintCntTrie = snapshot.mintCntTrie
}

func (c *Context) RefreshFromHash(rootInfo types.EngineInfo) error {
	var err error
	if c.epochTrie, err = newEpochTrie(rootInfo.EpochHash, c.EDB()); err != nil {
		return err
	}
	if c.candidateTrie, err = newCandidateTrie(rootInfo.CandidateHash, c.EDB()); err != nil {
		return err
	}
	if c.delegateTrie, err = newDelegateTrie(rootInfo.DelegateHash, c.EDB()); err != nil {
		return err
	}
	if c.voteTrie, err = newVoteTrie(rootInfo.VoteHash, c.EDB()); err != nil {
		return err
	}
	if c.mintCntTrie, err = newMintTrie(rootInfo.MintCntHash, c.EDB()); err != nil {
		return err
	}
	return nil
}

func (c *Context) KickOutCandidate(candidateAddr common.Address) error {
	candidate := candidateAddr.Bytes()
	if err := c.candidateTrie.t.TryDelete(candidate); err != nil {
		if _, ok := err.(*trie.MissingNodeError); !ok {
			return err
		}
	}
	iter := trie.NewIterator(c.delegateTrie.t.PrefixIterator(candidate))
	for iter.Next() {
		delegator := iter.Value
		key := append(candidate, delegator...)
		if err := c.delegateTrie.t.TryDelete(key); err != nil {
			if _, ok := err.(*trie.MissingNodeError); !ok {
				return err
			}
		}
		v, err := c.voteTrie.t.TryGet(delegator)
		if err != nil {
			if _, ok := err.(*trie.MissingNodeError); !ok {
				return err
			}
		}
		if err == nil && bytes.Equal(v, candidate) {
			err = c.voteTrie.t.TryDelete(delegator)
			if err != nil {
				if _, ok := err.(*trie.MissingNodeError); !ok {
					return err
				}
			}
		}
	}
	return nil
}

func (c *Context) BecomeCandidate(candidateAddr common.Address) error {
	candidate := candidateAddr.Bytes()
	return c.candidateTrie.t.TryUpdate(candidate, candidate)
}

func (c *Context) Delegate(delegatorAddr, candidateAddr common.Address) error {
	delegator, candidate := delegatorAddr.Bytes(), candidateAddr.Bytes()

	// the candidate must be candidate
	candidateInTrie, err := c.candidateTrie.t.TryGet(candidate)
	if err != nil {
		return err
	}

	//这里还得看是不是见证人
	validators, err := c.GetValidators()

	isValidator := false
	for _, v := range validators {
		if v == candidateAddr {
			isValidator = true
		}
	}
	if candidateInTrie == nil && !isValidator {
		return errors.New("invalid candidate to delegate")
	}

	// delete old candidate if exists
	oldCandidate, err := c.voteTrie.t.TryGet(delegator)
	if err != nil {
		if _, ok := err.(*trie.MissingNodeError); !ok {
			return err
		}
	}
	if oldCandidate != nil {
		c.delegateTrie.t.Delete(append(oldCandidate, delegator...))
	}
	if err = c.delegateTrie.t.TryUpdate(append(candidate, delegator...), delegator); err != nil {
		return err
	}

	return c.voteTrie.t.TryUpdate(delegator, candidate)
}

func (c *Context) UnDelegate(delegatorAddr, candidateAddr common.Address) error {
	delegator, candidate := delegatorAddr.Bytes(), candidateAddr.Bytes()

	// the candidate must be candidate
	candidateInTrie, err := c.candidateTrie.t.TryGet(candidate)
	if err != nil {
		return err
	}
	if candidateInTrie == nil {
		return errors.New("invalid candidate to undelegate")
	}

	oldCandidate, err := c.voteTrie.t.TryGet(delegator)
	if err != nil {
		return err
	}
	if !bytes.Equal(candidate, oldCandidate) {
		return errors.New("mismatch candidate to undelegate")
	}

	if err = c.delegateTrie.t.TryDelete(append(candidate, delegator...)); err != nil {
		return err
	}
	return c.voteTrie.t.TryDelete(delegator)
}

func commitTrie(t *Trie) (common.Hash, error) {
	rootHash, nodes, err := t.t.Commit(true)
	if err != nil {
		return types.EmptyRootHash, err
	}
	if nodes != nil {
		nodeSet := trie.NewWithNodeSet(nodes)
		err = t.d.Update(nodeSet)
		if err != nil {
			log.Debug("engine DB update", "err", err)
		}
		if err = t.d.Cap(0); err != nil {
			log.Warn("engine DB Cap", "err", err)
		}
	}
	return rootHash, nil
}

func (c *Context) Commit() (ei types.EngineInfo, err error) {
	if ei.EpochHash, err = commitTrie(c.epochTrie); err != nil {
		return
	}
	if ei.CandidateHash, err = commitTrie(c.candidateTrie); err != nil {
		return
	}
	if ei.DelegateHash, err = commitTrie(c.delegateTrie); err != nil {
		return
	}
	if ei.VoteHash, err = commitTrie(c.voteTrie); err != nil {
		return
	}
	if ei.MintCntHash, err = commitTrie(c.mintCntTrie); err != nil {
		return
	}
	return
}

func (c *Context) EDB() ethdb.KeyValueStore { return c.epochTrie.d.DiskDB() }

func (c *Context) GetValidators() ([]common.Address, error) {
	var validators []common.Address
	key := []byte("validator")
	validatorsRLP, err := c.epochTrie.t.TryGet(key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode validators: %s", err)
	}
	if err := rlp.DecodeBytes(validatorsRLP, &validators); err != nil {
		return nil, fmt.Errorf("failed to decode validators: %s", err)
	}
	return validators, nil
}

func encodeUint64ToBytes(number uint64) []byte {
	enc := make([]byte, 8)
	binary.BigEndian.PutUint64(enc, number)
	return enc
}

func (c *Context) GetValidatorsInEpoch(epochNumber uint64) ([]common.Address, error) {
	var validators []common.Address
	key := []byte("epoch-validator")
	key = append(key, encodeUint64ToBytes(epochNumber)...)
	validatorsRLP, err := c.epochTrie.t.TryGet(key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode validators: %s", err)
	}
	if err := rlp.DecodeBytes(validatorsRLP, &validators); err != nil {
		return nil, fmt.Errorf("failed to decode validators: %s", err)
	}
	return validators, nil
}

func (c *Context) GetDelegates() (map[common.Address]common.Address, error) {
	delegates := map[common.Address]common.Address{}

	ctxTrie := c.DelegateTrie()
	iterDelegate := ctxTrie.Iterator(nil)
	existDelegate := iterDelegate.Next()
	if !existDelegate {
		return delegates, errors.New("no delegates")
	}
	for existDelegate {
		addr := iterDelegate.Key
		candidate := iterDelegate.Value
		delegates[common.BytesToAddress(addr)] = common.BytesToAddress(candidate)
		existDelegate = iterDelegate.Next()
	}
	return delegates, nil
}

func (c *Context) SetValidators(validators []common.Address) error {
	key := []byte("validator")
	validatorsRLP, err := rlp.EncodeToBytes(validators)
	if err != nil {
		return fmt.Errorf("failed to encode validators to rlp bytes: %s", err)
	}
	return c.epochTrie.t.TryUpdate(key, validatorsRLP)
}

func (c *Context) SetValidatorsInEpoch(validators []common.Address, epochNumber uint64) error {
	key := []byte("epoch-validator")
	key = append(key, encodeUint64ToBytes(epochNumber)...)
	validatorsRLP, err := rlp.EncodeToBytes(validators)
	if err != nil {
		return fmt.Errorf("failed to encode validators to rlp bytes: %s", err)
	}
	return c.epochTrie.t.TryUpdate(key, validatorsRLP)
}

func (c *Context) CandidateTrie() *Trie { return c.candidateTrie }
func (c *Context) DelegateTrie() *Trie  { return c.delegateTrie }
func (c *Context) SetEpochTrie(t *Trie) { c.epochTrie = t }
