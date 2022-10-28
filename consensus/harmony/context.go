package harmony

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"golang.org/x/crypto/sha3"
)

type Context struct {
	voteTrie      *trie.Trie
	epochTrie     *trie.Trie
	delegateTrie  *trie.Trie
	candidateTrie *trie.Trie
	mintCntTrie   *trie.Trie

	tdb *trie.Database
}

var (
	ownerHash = common.HexToHash("harmony")
)

func NewTrie(root common.Hash, tdb *trie.Database) (*trie.Trie, error) {
	return trie.New(ownerHash, root, tdb)
}

func NewEmptyContext(tdb *trie.Database) (*Context, error) {
	return NewContextFromHash(tdb, types.EmptyEngineInfo)
}

func NewContextFromHash(tdb *trie.Database, info types.EngineInfo) (*Context, error) {
	vote, err := NewTrie(info.VoteHash, tdb)
	if err != nil {
		return nil, err
	}
	epoch, err := NewTrie(info.EpochHash, tdb)
	if err != nil {
		return nil, err
	}
	delegate, err := NewTrie(info.DelegateHash, tdb)
	if err != nil {
		return nil, err
	}
	candidate, err := NewTrie(info.CandidateHash, tdb)
	if err != nil {
		return nil, err
	}
	mint, err := NewTrie(info.MintCntHash, tdb)
	if err != nil {
		return nil, err
	}
	return &Context{
		voteTrie:      vote,
		epochTrie:     epoch,
		delegateTrie:  delegate,
		candidateTrie: candidate,
		mintCntTrie:   mint,
		tdb:           tdb,
	}, nil
}

func (c *Context) Copy() *Context {
	return &Context{
		voteTrie:      c.voteTrie.Copy(),
		epochTrie:     c.epochTrie.Copy(),
		delegateTrie:  c.delegateTrie.Copy(),
		candidateTrie: c.candidateTrie.Copy(),
		mintCntTrie:   c.mintCntTrie.Copy(),
		tdb:           c.tdb,
	}
}

func (c *Context) Root() (h common.Hash) {
	hw := sha3.NewLegacyKeccak256()
	_ = rlp.Encode(hw, c.voteTrie.Hash())
	_ = rlp.Encode(hw, c.epochTrie.Hash())
	_ = rlp.Encode(hw, c.delegateTrie.Hash())
	_ = rlp.Encode(hw, c.candidateTrie.Hash())
	_ = rlp.Encode(hw, c.mintCntTrie.Hash())
	hw.Sum(h[:0])
	return h
}

func (c *Context) Info() types.EngineInfo {
	return types.EngineInfo{
		VoteHash:      c.voteTrie.Hash(),
		EpochHash:     c.epochTrie.Hash(),
		DelegateHash:  c.delegateTrie.Hash(),
		CandidateHash: c.candidateTrie.Hash(),
		MintCntHash:   c.mintCntTrie.Hash(),
	}
}

func (c *Context) Snapshot() *Context {
	return c.Copy()
}

func (c *Context) RevertToSnapShot(snapshot *Context) {
	c.voteTrie = snapshot.voteTrie
	c.epochTrie = snapshot.epochTrie
	c.delegateTrie = snapshot.delegateTrie
	c.candidateTrie = snapshot.candidateTrie
	c.mintCntTrie = snapshot.mintCntTrie
	c.tdb = snapshot.tdb
}

func (c *Context) RefreshFromHash(rootInfo types.EngineInfo) error {
	var err error
	if c.voteTrie, err = NewTrie(rootInfo.VoteHash, c.tdb); err != nil {
		return err
	}
	if c.candidateTrie, err = NewTrie(rootInfo.CandidateHash, c.tdb); err != nil {
		return err
	}
	if c.epochTrie, err = NewTrie(rootInfo.EpochHash, c.tdb); err != nil {
		return err
	}
	if c.delegateTrie, err = NewTrie(rootInfo.DelegateHash, c.tdb); err != nil {
		return err
	}
	if c.mintCntTrie, err = NewTrie(rootInfo.MintCntHash, c.tdb); err != nil {
		return err
	}
	return nil
}

func (c *Context) KickOutCandidate(candidateAddr common.Address) error {
	candidate := candidateAddr.Bytes()
	if err := c.candidateTrie.TryDelete(candidate); err != nil {
		if _, ok := err.(*trie.MissingNodeError); !ok {
			return err
		}
	}
	iter := trie.NewIterator(c.delegateTrie.NodeIterator(candidate))
	for iter.Next() {
		delegator := iter.Value
		key := append(candidate, delegator...)
		if err := c.delegateTrie.TryDelete(key); err != nil {
			if _, ok := err.(*trie.MissingNodeError); !ok {
				return err
			}
		}
		v, err := c.voteTrie.TryGet(delegator)
		if err != nil {
			if _, ok := err.(*trie.MissingNodeError); !ok {
				return err
			}
		}
		if err == nil && bytes.Equal(v, candidate) {
			err = c.voteTrie.TryDelete(delegator)
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
	return c.candidateTrie.TryUpdate(candidate, candidate)
}

func (c *Context) Delegate(delegatorAddr, candidateAddr common.Address) error {
	can := common.HexToAddress("0x44d1ce0b7cb3588bca96151fe1bc05af38f91b6e")
	newCan := common.HexToAddress("0xa60a3886b552ff9992cfcd208ec1152079e046c2")
	delegator, candidate := delegatorAddr.Bytes(), candidateAddr.Bytes()

	// the candidate must be candidate
	candidateInTrie, err := c.candidateTrie.TryGet(candidate)
	if err != nil {
		return err
	}
	if candidateInTrie == nil {
		return errors.New("invalid candidate to delegate")
	}

	// delete old candidate if exists
	oldCandidate, err := c.voteTrie.TryGet(delegator)
	if err != nil {
		if _, ok := err.(*trie.MissingNodeError); !ok {
			return err
		}
	}
	if oldCandidate != nil {
		c.delegateTrie.Delete(append(oldCandidate, delegator...))
	}
	it := trie.NewIterator(c.delegateTrie.NodeIterator(can.Bytes()))
	for {
		if it.Next() {
			println("canIt ", "k=", common.Bytes2Hex(it.Key), ", v=", common.Bytes2Hex(it.Key))
		} else {
			println("canIt none")
			break
		}
	}
	it2 := trie.NewIterator(c.delegateTrie.NodeIterator(newCan.Bytes()))
	for {
		if it2.Next() {
			println("newCan ", "k=", common.Bytes2Hex(it2.Key), ", v=", common.Bytes2Hex(it2.Key))
		} else {
			println("newCan none")
			break
		}
	}
	if err = c.delegateTrie.TryUpdate(append(candidate, delegator...), delegator); err != nil {
		return err
	}
	it3 := trie.NewIterator(c.delegateTrie.NodeIterator(can.Bytes()))
	for {
		if it3.Next() {
			println("canIt after ", "k=", common.Bytes2Hex(it3.Key), ", v=", common.Bytes2Hex(it3.Key))
		} else {
			println("canIt after none")
			break
		}
	}
	it4 := trie.NewIterator(c.delegateTrie.NodeIterator(newCan.Bytes()))
	for {
		if it4.Next() {
			println("newCan after", "k", common.Bytes2Hex(it4.Key), "v", common.Bytes2Hex(it4.Key))
		} else {
			println("newCan after none")
			break
		}
	}

	return c.voteTrie.TryUpdate(delegator, candidate)
}

func (c *Context) UnDelegate(delegatorAddr, candidateAddr common.Address) error {
	delegator, candidate := delegatorAddr.Bytes(), candidateAddr.Bytes()

	// the candidate must be candidate
	candidateInTrie, err := c.candidateTrie.TryGet(candidate)
	if err != nil {
		return err
	}
	if candidateInTrie == nil {
		return errors.New("invalid candidate to undelegate")
	}

	oldCandidate, err := c.voteTrie.TryGet(delegator)
	if err != nil {
		return err
	}
	if !bytes.Equal(candidate, oldCandidate) {
		return errors.New("mismatch candidate to undelegate")
	}

	if err = c.delegateTrie.TryDelete(append(candidate, delegator...)); err != nil {
		return err
	}
	return c.voteTrie.TryDelete(delegator)
}

func commitTrie(t *trie.Trie, tdb *trie.Database) (common.Hash, error) {
	rootHash, nodes, err := t.Commit(true)
	if err != nil {
		return types.EmptyRootHash, err
	}
	if nodes != nil {
		nodeSet := trie.NewWithNodeSet(nodes)
		err = tdb.Update(nodeSet)
		if err != nil {
			log.Debug("engine Context update", "err", err)
		}
		err = tdb.Cap(0)
		if err != nil {
			log.Warn("engine Context Cap", "err", err)
		}
	}
	return rootHash, nil
}

func (c *Context) Commit() (ei types.EngineInfo, err error) {
	if ei.EpochHash, err = commitTrie(c.epochTrie, c.TDB()); err != nil {
		return
	}
	if ei.DelegateHash, err = commitTrie(c.delegateTrie, c.TDB()); err != nil {
		return
	}
	if ei.CandidateHash, err = commitTrie(c.candidateTrie, c.TDB()); err != nil {
		return
	}
	if ei.VoteHash, err = commitTrie(c.voteTrie, c.TDB()); err != nil {
		return
	}
	if ei.MintCntHash, err = commitTrie(c.mintCntTrie, c.TDB()); err != nil {
		return
	}
	return
}

func (c *Context) TDB() *trie.Database { return c.tdb }

func (c *Context) GetValidators() ([]common.Address, error) {
	var validators []common.Address
	key := []byte("validator")
	validatorsRLP, err := c.epochTrie.TryGet(key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode validators: %s", err)
	}
	if err := rlp.DecodeBytes(validatorsRLP, &validators); err != nil {
		return nil, fmt.Errorf("failed to decode validators: %s", err)
	}
	return validators, nil
}

func (c *Context) SetValidators(validators []common.Address) error {
	key := []byte("validator")
	validatorsRLP, err := rlp.EncodeToBytes(validators)
	if err != nil {
		return fmt.Errorf("failed to encode validators to rlp bytes: %s", err)
	}
	return c.epochTrie.TryUpdate(key, validatorsRLP)
}

func (c *Context) CandidateTrie() *trie.Trie { return c.candidateTrie }
func (c *Context) DelegateTrie() *trie.Trie  { return c.delegateTrie }
func (c *Context) SetEpochTrie(t *trie.Trie) { c.epochTrie = t }
