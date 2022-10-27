package harmony

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/stretchr/testify/assert"
)

func TestContextSnapshot(t *testing.T) {
	db := trie.NewDatabase(rawdb.NewMemoryDatabase())
	ctx, err := NewEmptyContext(db)
	assert.Nil(t, err)

	snapshot := ctx.Snapshot()
	assert.Equal(t, ctx.Root(), snapshot.Root())
	assert.Equal(t, ctx, snapshot)

	// change ctx
	assert.Nil(t, ctx.BecomeCandidate(common.HexToAddress("0x44d1ce0b7cb3588bca96151fe1bc05af38f91b6c")))
	assert.NotEqual(t, ctx.Root(), snapshot.Root())

	// revert snapshot
	ctx.RevertToSnapShot(snapshot)
	assert.Equal(t, ctx.Root(), snapshot.Root())
	assert.Equal(t, ctx, snapshot)
}

func TestContextBecomeCandidate(t *testing.T) {
	candidates := []common.Address{
		common.HexToAddress("0x44d1ce0b7cb3588bca96151fe1bc05af38f91b6e"),
		common.HexToAddress("0xa60a3886b552ff9992cfcd208ec1152079e046c2"),
		common.HexToAddress("0x4e080e49f62694554871e669aeb4ebe17c4a9670"),
	}
	db := trie.NewDatabase(rawdb.NewMemoryDatabase())
	ctx, err := NewEmptyContext(db)
	assert.Nil(t, err)
	for _, candidate := range candidates {
		assert.Nil(t, ctx.BecomeCandidate(candidate))
	}

	candidateMap := map[common.Address]bool{}
	candidateIter := trie.NewIterator(ctx.trie.PrefixIterator(nil, CandidatePrefix))
	for candidateIter.Next() {
		candidateMap[common.BytesToAddress(candidateIter.Value)] = true
	}
	assert.Equal(t, len(candidates), len(candidateMap))
	for _, candidate := range candidates {
		assert.True(t, candidateMap[candidate])
	}
}

func TestContextKickOutCandidate(t *testing.T) {
	candidates := []common.Address{
		common.HexToAddress("0x44d1ce0b7cb3588bca96151fe1bc05af38f91b6e"),
		common.HexToAddress("0xa60a3886b552ff9992cfcd208ec1152079e046c2"),
		common.HexToAddress("0x4e080e49f62694554871e669aeb4ebe17c4a9670"),
	}
	db := trie.NewDatabase(rawdb.NewMemoryDatabase())
	ctx, err := NewEmptyContext(db)
	assert.Nil(t, err)
	for _, candidate := range candidates {
		assert.Nil(t, ctx.BecomeCandidate(candidate))
		assert.Nil(t, ctx.Delegate(candidate, candidate))
	}

	kickIdx := 1
	assert.Nil(t, ctx.KickOutCandidate(candidates[kickIdx]))
	candidateMap := map[common.Address]bool{}
	candidateIter := trie.NewIterator(ctx.trie.PrefixIterator(nil, CandidatePrefix))
	for candidateIter.Next() {
		candidateMap[common.BytesToAddress(candidateIter.Value)] = true
	}
	voteIter := trie.NewIterator(ctx.trie.PrefixIterator(nil, votePrefix))
	voteMap := map[common.Address]bool{}
	for voteIter.Next() {
		voteMap[common.BytesToAddress(voteIter.Value)] = true
	}
	for i, candidate := range candidates {
		delegateIter := trie.NewIterator(ctx.trie.PrefixIterator(candidate.Bytes(), DelegatePrefix))
		if i == kickIdx {
			assert.False(t, delegateIter.Next())
			assert.False(t, candidateMap[candidate])
			assert.False(t, voteMap[candidate])
			continue
		}
		assert.True(t, delegateIter.Next())
		assert.True(t, candidateMap[candidate])
		assert.True(t, voteMap[candidate])
	}
}

func TestContextDelegateAndUnDelegate(t *testing.T) {
	candidate := common.HexToAddress("0x44d1ce0b7cb3588bca96151fe1bc05af38f91b6e")
	newCandidate := common.HexToAddress("0xa60a3886b552ff9992cfcd208ec1152079e046c2")
	delegator := common.HexToAddress("0x4e080e49f62694554871e669aeb4ebe17c4a9670")
	db := trie.NewDatabase(rawdb.NewMemoryDatabase())
	ctx, err := NewEmptyContext(db)
	assert.Nil(t, err)
	assert.Nil(t, ctx.BecomeCandidate(candidate))
	assert.Nil(t, ctx.BecomeCandidate(newCandidate))

	// delegator delegate to not exist candidate
	candidateIter := trie.NewIterator(ctx.trie.PrefixIterator(nil, CandidatePrefix))
	candidateMap := map[string]bool{}
	for candidateIter.Next() {
		candidateMap[string(candidateIter.Value)] = true
	}
	assert.NotNil(t, ctx.Delegate(delegator, common.HexToAddress("0xab")))

	// delegator delegate to old candidate
	assert.Nil(t, ctx.Delegate(delegator, candidate))
	delegateIter := trie.NewIterator(ctx.trie.PrefixIterator(candidate.Bytes(), DelegatePrefix))
	if assert.True(t, delegateIter.Next()) {
		assert.Equal(t, append(DelegatePrefix, append(candidate.Bytes(), delegator.Bytes()...)...), delegateIter.Key)
		assert.Equal(t, delegator, common.BytesToAddress(delegateIter.Value))
	}
	voteIter := trie.NewIterator(ctx.trie.PrefixIterator(nil, votePrefix))
	if assert.True(t, voteIter.Next()) {
		assert.Equal(t, append(votePrefix, delegator.Bytes()...), voteIter.Key)
		assert.Equal(t, candidate, common.BytesToAddress(voteIter.Value))
	}

	// delegator delegate to new candidate
	assert.Nil(t, ctx.Delegate(delegator, newCandidate))
	delegateIter = trie.NewIterator(ctx.trie.PrefixIterator(candidate.Bytes(), DelegatePrefix))
	assert.False(t, delegateIter.Next())
	delegateIter = trie.NewIterator(ctx.trie.PrefixIterator(newCandidate.Bytes(), DelegatePrefix))
	if assert.True(t, delegateIter.Next()) {
		assert.Equal(t, append(DelegatePrefix, append(newCandidate.Bytes(), delegator.Bytes()...)...), delegateIter.Key)
		assert.Equal(t, delegator, common.BytesToAddress(delegateIter.Value))
	}
	voteIter = trie.NewIterator(ctx.trie.PrefixIterator(nil, votePrefix))
	if assert.True(t, voteIter.Next()) {
		assert.Equal(t, append(votePrefix, delegator.Bytes()...), voteIter.Key)
		assert.Equal(t, newCandidate, common.BytesToAddress(voteIter.Value))
	}

	// delegator undelegate to not exist candidate
	assert.NotNil(t, ctx.UnDelegate(common.HexToAddress("0x00"), candidate))

	// delegator undelegate to old candidate
	assert.NotNil(t, ctx.UnDelegate(delegator, candidate))

	// delegator undelegate to new candidate
	assert.Nil(t, ctx.UnDelegate(delegator, newCandidate))
	delegateIter = trie.NewIterator(ctx.trie.PrefixIterator(newCandidate.Bytes(), DelegatePrefix))
	assert.False(t, delegateIter.Next())
	voteIter = trie.NewIterator(ctx.trie.PrefixIterator(nil, votePrefix))
	assert.False(t, voteIter.Next())
}

func TestContextValidators(t *testing.T) {
	validators := []common.Address{
		common.HexToAddress("0x44d1ce0b7cb3588bca96151fe1bc05af38f91b6e"),
		common.HexToAddress("0xa60a3886b552ff9992cfcd208ec1152079e046c2"),
		common.HexToAddress("0x4e080e49f62694554871e669aeb4ebe17c4a9670"),
	}

	db := trie.NewDatabase(rawdb.NewMemoryDatabase())
	ctx, err := NewEmptyContext(db)
	assert.Nil(t, err)

	assert.Nil(t, ctx.SetValidators(validators))

	result, err := ctx.GetValidators()
	assert.Nil(t, err)
	assert.Equal(t, len(validators), len(result))
	validatorMap := map[common.Address]bool{}
	for _, validator := range validators {
		validatorMap[validator] = true
	}
	for _, validator := range result {
		assert.True(t, validatorMap[validator])
	}
}
