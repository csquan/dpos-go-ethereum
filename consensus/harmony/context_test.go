package harmony

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/stretchr/testify/assert"
)

func TestContextSnapshot(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
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
	db := rawdb.NewMemoryDatabase()
	ctx, err := NewEmptyContext(db)
	assert.Nil(t, err)
	for _, candidate := range candidates {
		assert.Nil(t, ctx.BecomeCandidate(candidate))
	}

	candidateMap := map[common.Address]bool{}
	candidateIter := ctx.candidateTrie.Iterator(nil)
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
	db := rawdb.NewMemoryDatabase()
	ctx, err := NewEmptyContext(db)
	assert.Nil(t, err)
	for _, candidate := range candidates {
		assert.Nil(t, ctx.BecomeCandidate(candidate))
		assert.Nil(t, ctx.Delegate(candidate, candidate))
	}

	kickIdx := 1
	assert.Nil(t, ctx.KickOutCandidate(candidates[kickIdx]))
	candidateMap := map[common.Address]bool{}
	candidateIter := ctx.candidateTrie.Iterator(nil)
	for candidateIter.Next() {
		candidateMap[common.BytesToAddress(candidateIter.Value)] = true
	}
	voteIter := ctx.voteTrie.Iterator(nil)
	voteMap := map[common.Address]bool{}
	for voteIter.Next() {
		voteMap[common.BytesToAddress(voteIter.Value)] = true
	}
	for i, candidate := range candidates {
		delegateIter := ctx.delegateTrie.Iterator(candidate.Bytes())
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
	db := rawdb.NewMemoryDatabase()
	ctx, err := NewEmptyContext(db)
	assert.Nil(t, err)
	assert.Nil(t, ctx.BecomeCandidate(candidate))
	assert.Nil(t, ctx.BecomeCandidate(newCandidate))

	// delegator delegate to not exist candidate
	canIter0 := ctx.candidateTrie.Iterator(nil)
	candidateMap := map[string]bool{}
	for canIter0.Next() {
		candidateMap[string(canIter0.Value)] = true
	}
	assert.NotNil(t, ctx.Delegate(delegator, common.HexToAddress("0xab")))

	// delegator delegate to old candidate
	assert.Nil(t, ctx.Delegate(delegator, candidate))
	deIterCan := ctx.delegateTrie.Iterator(candidate.Bytes())
	if assert.True(t, deIterCan.Next()) {
		assert.Equal(t, append(candidate.Bytes(), delegator.Bytes()...), deIterCan.Key)
		assert.Equal(t, delegator, common.BytesToAddress(deIterCan.Value))
	}
	voteIter0 := ctx.voteTrie.Iterator(nil)
	if assert.True(t, voteIter0.Next()) {
		assert.Equal(t, delegator.Bytes(), voteIter0.Key)
		assert.Equal(t, candidate, common.BytesToAddress(voteIter0.Value))
	}

	// delegator delegate to new candidate
	assert.Nil(t, ctx.Delegate(delegator, newCandidate))
	deIterCan1 := ctx.delegateTrie.Iterator(candidate.Bytes())
	assert.False(t, deIterCan1.Next())
	deIterCanNew := ctx.delegateTrie.Iterator(newCandidate.Bytes())
	if assert.True(t, deIterCanNew.Next()) {
		assert.Equal(t, append(newCandidate.Bytes(), delegator.Bytes()...), deIterCanNew.Key)
		assert.Equal(t, delegator.Bytes(), deIterCanNew.Value)
	}
	voteIterN := ctx.voteTrie.Iterator(nil)
	if assert.True(t, voteIterN.Next()) {
		assert.Equal(t, delegator.Bytes(), voteIterN.Key)
		assert.Equal(t, newCandidate.Bytes(), voteIterN.Value)
	}

	// delegator undelegate to not exist candidate
	assert.NotNil(t, ctx.UnDelegate(common.HexToAddress("0x00"), candidate))

	// delegator undelegate to old candidate
	assert.NotNil(t, ctx.UnDelegate(delegator, candidate))

	// delegator undelegate to new candidate
	assert.Nil(t, ctx.UnDelegate(delegator, newCandidate))
	deIterNewCan := ctx.delegateTrie.Iterator(newCandidate.Bytes())
	assert.False(t, deIterNewCan.Next())
	voteIter1 := ctx.voteTrie.Iterator(nil)
	assert.False(t, voteIter1.Next())
}

func TestContextReDelegate(t *testing.T) {
	validatorStr := "44d1ce0b7cb3588bca96151fe1bc05af38f91b6e"
	newCandidateStr := "a60a3886b552ff9992cfcd208ec1152079e046c2"
	validator := common.HexToAddress(validatorStr)
	newCandidate := common.HexToAddress(newCandidateStr)
	db := rawdb.NewMemoryDatabase()
	ctx, err := NewEmptyContext(db)
	assert.Nil(t, err)
	assert.Nil(t, ctx.BecomeCandidate(validator))
	assert.Nil(t, ctx.Delegate(validator, validator))
	assert.Nil(t, ctx.BecomeCandidate(newCandidate))
	assert.Nil(t, ctx.Delegate(validator, newCandidate))

	// delegator delegate to not exist candidate
	canIter0 := ctx.candidateTrie.Iterator(nil)
	candidateMap := map[string]bool{}
	for canIter0.Next() {
		candidateMap[common.Bytes2Hex(canIter0.Value)] = true
	}
	assert.Equal(t, 2, len(candidateMap))

	// delegator delegate to old candidate
	deIterCan := ctx.delegateTrie.Iterator(validator.Bytes())
	delegateMap := map[string]bool{}
	for deIterCan.Next() {
		delegateMap[common.Bytes2Hex(deIterCan.Value)] = true
	}
	assert.Equal(t, 0, len(delegateMap))

	newDeIterCan := ctx.delegateTrie.Iterator(newCandidate.Bytes())
	delegateMap2 := map[string]bool{}
	delegateKey2 := map[string]bool{}
	for newDeIterCan.Next() {
		delegateMap2[common.Bytes2Hex(newDeIterCan.Value)] = true
		delegateKey2[common.Bytes2Hex(newDeIterCan.Key)] = true
	}
	assert.Equal(t, 1, len(delegateMap2))
	assert.True(t, delegateMap2[validatorStr])
	assert.True(t, delegateKey2[newCandidateStr+validatorStr])

	voteIter0 := ctx.voteTrie.Iterator(nil)
	voteMap := map[string]bool{}
	for voteIter0.Next() {
		voteMap[common.Bytes2Hex(voteIter0.Value)] = true
	}
	assert.Equal(t, 1, len(voteMap))
}

func TestContextValidators(t *testing.T) {
	validators := []common.Address{
		common.HexToAddress("0x44d1ce0b7cb3588bca96151fe1bc05af38f91b6e"),
		common.HexToAddress("0xa60a3886b552ff9992cfcd208ec1152079e046c2"),
		common.HexToAddress("0x4e080e49f62694554871e669aeb4ebe17c4a9670"),
	}

	db := rawdb.NewMemoryDatabase()
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
