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
	trie *trie.Trie

	db *trie.Database
}

var (
	epochPrefix     = []byte("epoch-")
	DelegatePrefix  = []byte("delegate-")
	votePrefix      = []byte("vote-")
	CandidatePrefix = []byte("candidate-")
	mintCntPrefix   = []byte("mintCnt-")
)

func NewTrie(root common.Hash, db *trie.Database) (*trie.Trie, error) {
	return trie.New(common.Hash{}, root, db)
}

func NewContext(db *trie.Database) (*Context, error) {
	t, err := NewTrie(common.Hash{}, db)
	if err != nil {
		return nil, err
	}
	return &Context{
		trie: t,
		db:   db,
	}, nil
}

func NewContextFromHash(db *trie.Database, rootHash common.Hash) (*Context, error) {
	t, err := NewTrie(rootHash, db)
	if err != nil {
		return nil, err
	}
	return &Context{
		trie: t,
		db:   db,
	}, nil
}

func (c *Context) Copy() *Context {
	return &Context{
		trie: c.trie,
		db:   c.db,
	}
}

func (c *Context) Root() (h common.Hash) {
	hw := sha3.NewLegacyKeccak256()
	rlp.Encode(hw, c.trie.Hash())
	hw.Sum(h[:0])
	return h
}

func (c *Context) Snapshot() *Context {
	return c.Copy()
}

func (c *Context) RevertToSnapShot(snapshot *Context) {
	c.trie = snapshot.trie
}

func (c *Context) FromHash(rootHash common.Hash) error {
	var err error
	c.trie, err = NewTrie(rootHash, c.db)
	return err
}

func (c *Context) KickOutCandidate(candidateAddr common.Address) error {
	candidate := candidateAddr.Bytes()
	err := c.trie.TryDeleteWithPrefix(candidate, CandidatePrefix)
	if err != nil {
		if _, ok := err.(*trie.MissingNodeError); !ok {
			return err
		}
	}
	iter := trie.NewIterator(c.trie.PrefixIterator(candidate, DelegatePrefix))
	for iter.Next() {
		delegator := iter.Value
		key := append(candidate, delegator...)
		err = c.trie.TryDeleteWithPrefix(key, DelegatePrefix)
		if err != nil {
			if _, ok := err.(*trie.MissingNodeError); !ok {
				return err
			}
		}
		v, err := c.trie.TryGetWithPrefix(delegator, votePrefix)
		if err != nil {
			if _, ok := err.(*trie.MissingNodeError); !ok {
				return err
			}
		}
		if err == nil && bytes.Equal(v, candidate) {
			err = c.trie.TryDeleteWithPrefix(delegator, votePrefix)
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
	return c.trie.TryUpdateWithPrefix(candidate, candidate, CandidatePrefix)
}

func (c *Context) Delegate(delegatorAddr, candidateAddr common.Address) error {
	delegator, candidate := delegatorAddr.Bytes(), candidateAddr.Bytes()

	// the candidate must be candidate
	candidateInTrie, err := c.trie.TryGetWithPrefix(candidate, CandidatePrefix)
	if err != nil {
		return err
	}
	if candidateInTrie == nil {
		return errors.New("invalid candidate to delegate")
	}

	// delete old candidate if exists
	oldCandidate, err := c.trie.TryGetWithPrefix(delegator, votePrefix)
	if err != nil {
		if _, ok := err.(*trie.MissingNodeError); !ok {
			return err
		}
	}
	if oldCandidate != nil {
		if err = c.trie.TryDeleteWithPrefix(append(oldCandidate, delegator...), DelegatePrefix); err != nil {
			return err
		}
	}
	if err = c.trie.TryUpdateWithPrefix(append(candidate, delegator...), delegator, DelegatePrefix); err != nil {
		return err
	}
	return c.trie.TryUpdateWithPrefix(delegator, candidate, votePrefix)
}

func (c *Context) UnDelegate(delegatorAddr, candidateAddr common.Address) error {
	delegator, candidate := delegatorAddr.Bytes(), candidateAddr.Bytes()

	// the candidate must be candidate
	candidateInTrie, err := c.trie.TryGetWithPrefix(candidate, CandidatePrefix)
	if err != nil {
		return err
	}
	if candidateInTrie == nil {
		return errors.New("invalid candidate to undelegate")
	}

	oldCandidate, err := c.trie.TryGetWithPrefix(delegator, votePrefix)
	if err != nil {
		return err
	}
	if !bytes.Equal(candidate, oldCandidate) {
		return errors.New("mismatch candidate to undelegate")
	}

	if err = c.trie.TryDeleteWithPrefix(append(candidate, delegator...), DelegatePrefix); err != nil {
		return err
	}
	return c.trie.TryDeleteWithPrefix(delegator, votePrefix)
}

func (c *Context) Commit() (common.Hash, error) {
	rootHash, nodes, err := c.trie.Commit(true)
	if err != nil {
		return types.EmptyRootHash, err
	}
	err = c.db.Update(trie.NewWithNodeSet(nodes))
	if err != nil {
		log.Debug("db update", "err", err)
		return types.EmptyRootHash, err
	}
	return rootHash, nil
}

func (c *Context) Trie() *trie.Trie        { return c.trie }
func (c *Context) DB() *trie.Database      { return c.db }
func (c *Context) SetTrie(trie *trie.Trie) { c.trie = trie }

func (c *Context) GetValidators() ([]common.Address, error) {
	var validators []common.Address
	key := []byte("validator")
	validatorsRLP, err := c.trie.TryGetWithPrefix(key, epochPrefix)
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
	return c.trie.TryUpdateWithPrefix(key, validatorsRLP, epochPrefix)
}
