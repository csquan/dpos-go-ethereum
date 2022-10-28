package harmony

import (
	"math/big"
	"strconv"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
)

func TestEpochContextCountVotes(t *testing.T) {
	voteMap := map[common.Address][]common.Address{
		common.HexToAddress("0x44d1ce0b7cb3588bca96151fe1bc05af38f91b6e"): {
			common.HexToAddress("0xb040353ec0f2c113d5639444f7253681aecda1f8"),
		},
		common.HexToAddress("0xa60a3886b552ff9992cfcd208ec1152079e046c2"): {
			common.HexToAddress("0x14432e15f21237013017fa6ee90fc99433dec82c"),
			common.HexToAddress("0x9f30d0e5c9c88cade54cd1adecf6bc2c7e0e5af6"),
		},
		common.HexToAddress("0x4e080e49f62694554871e669aeb4ebe17c4a9670"): {
			common.HexToAddress("0xd83b44a3719720ec54cdb9f54c0202de68f1ebcb"),
			common.HexToAddress("0x56cc452e450551b7b9cffe25084a069e8c1e9441"),
			common.HexToAddress("0xbcfcb3fa8250be4f2bf2b1e70e1da500c668377b"),
		},
		common.HexToAddress("0x9d9667c71bb09d6ca7c3ed12bfe5e7be24e2ffe1"): {},
	}
	balance := int64(5)
	db := rawdb.NewMemoryDatabase()
	stateDB, err := state.New(common.Hash{}, state.NewDatabase(db), nil)
	assert.Nil(t, err)
	ctx, err := NewEmptyContext(db)
	assert.Nil(t, err)

	epochContext := &EpochContext{
		Context: ctx,
		stateDB: stateDB,
	}
	_, err = epochContext.countVotes()
	assert.NotNil(t, err)

	for candidate, electors := range voteMap {
		assert.Nil(t, ctx.BecomeCandidate(candidate))
		for _, elector := range electors {
			stateDB.SetBalance(elector, big.NewInt(balance))
			assert.Nil(t, ctx.Delegate(elector, candidate))
		}
	}
	result, err := epochContext.countVotes()
	assert.Nil(t, err)
	assert.Equal(t, len(voteMap), len(result))
	for candidate, electors := range voteMap {
		voteCount, ok := result[candidate]
		assert.True(t, ok)
		assert.Equal(t, balance*int64(len(electors)), voteCount.Int64())
	}
}

func TestLookupValidator(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	ctx, err := NewEmptyContext(db)
	mockEpochContext := &EpochContext{
		Context: ctx,
	}
	validators := []common.Address{
		common.BytesToAddress([]byte("addr1")),
		common.BytesToAddress([]byte("addr2")),
		common.BytesToAddress([]byte("addr3")),
	}
	mockEpochContext.Context.SetValidators(validators)
	for i, expected := range validators {
		got, _ := mockEpochContext.lookupValidator(uint64(i) * blockInterval)
		if got != expected {
			t.Errorf("Failed to test lookup validator, %s was expected but got %s", expected.String(), got.String())
		}
	}
	_, err = mockEpochContext.lookupValidator(blockInterval - 1)
	if err != ErrInvalidMintBlockTime {
		t.Errorf("Failed to test lookup validator. err '%v' was expected but got '%v'", ErrInvalidMintBlockTime, err)
	}
}

func TestEpochContextKickoutValidator(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	stateDB, _ := state.New(common.Hash{}, state.NewDatabase(db), nil)
	ctx, err := NewEmptyContext(db)
	assert.Nil(t, err)
	epochContext := &EpochContext{
		TimeStamp: epochInterval,
		Context:   ctx,
		stateDB:   stateDB,
	}
	atLeastMintCnt := epochInterval / blockInterval / maxValidatorSize / 2
	testEpoch := uint64(1)

	// no validator can be kickout, because all validators mint enough block at least
	validators := []common.Address{}
	for i := 0; i < maxValidatorSize; i++ {
		validator := common.BytesToAddress([]byte("addr" + strconv.Itoa(i)))
		validators = append(validators, validator)
		assert.Nil(t, ctx.BecomeCandidate(validator))
		setTestMintCnt(ctx, testEpoch, validator, atLeastMintCnt)
	}
	assert.Nil(t, ctx.SetValidators(validators))
	assert.Nil(t, ctx.BecomeCandidate(common.BytesToAddress([]byte("addr"))))
	assert.Nil(t, epochContext.kickOutValidator(testEpoch))
	candidateMap := getCandidates(ctx)
	assert.Equal(t, maxValidatorSize+1, len(candidateMap))

	// atLeast a safeSize count candidate will reserve
	ctx, err = NewEmptyContext(db)
	assert.Nil(t, err)
	epochContext = &EpochContext{
		TimeStamp: epochInterval,
		Context:   ctx,
		stateDB:   stateDB,
	}
	validators = []common.Address{}
	for i := 0; i < maxValidatorSize; i++ {
		validator := common.BytesToAddress([]byte("addr" + strconv.Itoa(i)))
		validators = append(validators, validator)
		assert.Nil(t, ctx.BecomeCandidate(validator))
		setTestMintCnt(ctx, testEpoch, validator, atLeastMintCnt-uint64(i)-1)
	}
	assert.Nil(t, ctx.SetValidators(validators))
	assert.Nil(t, epochContext.kickOutValidator(testEpoch))
	candidateMap = getCandidates(ctx)
	assert.Equal(t, safeSize, len(candidateMap))
	for i := maxValidatorSize - 1; i >= safeSize; i-- {
		assert.False(t, candidateMap[common.BytesToAddress([]byte("addr"+strconv.Itoa(i)))])
	}

	// all validator will be kick-out, because all validators didn't mint enough block at least
	ctx, err = NewEmptyContext(db)
	assert.Nil(t, err)
	epochContext = &EpochContext{
		TimeStamp: epochInterval,
		Context:   ctx,
		stateDB:   stateDB,
	}
	validators = []common.Address{}
	for i := 0; i < maxValidatorSize; i++ {
		validator := common.BytesToAddress([]byte("addr" + strconv.Itoa(i)))
		validators = append(validators, validator)
		assert.Nil(t, ctx.BecomeCandidate(validator))
		setTestMintCnt(ctx, testEpoch, validator, atLeastMintCnt-1)
	}
	for i := maxValidatorSize; i < maxValidatorSize*2; i++ {
		candidate := common.BytesToAddress([]byte("addr" + strconv.Itoa(i)))
		assert.Nil(t, ctx.BecomeCandidate(candidate))
	}
	assert.Nil(t, ctx.SetValidators(validators))
	assert.Nil(t, epochContext.kickOutValidator(testEpoch))
	candidateMap = getCandidates(ctx)
	assert.Equal(t, maxValidatorSize, len(candidateMap))

	// only one validator mint count is not enough
	ctx, err = NewEmptyContext(db)
	assert.Nil(t, err)
	epochContext = &EpochContext{
		TimeStamp: epochInterval,
		Context:   ctx,
		stateDB:   stateDB,
	}
	validators = []common.Address{}
	for i := 0; i < maxValidatorSize; i++ {
		validator := common.BytesToAddress([]byte("addr" + strconv.Itoa(i)))
		validators = append(validators, validator)
		assert.Nil(t, ctx.BecomeCandidate(validator))
		if i == 0 {
			setTestMintCnt(ctx, testEpoch, validator, atLeastMintCnt-1)
		} else {
			setTestMintCnt(ctx, testEpoch, validator, atLeastMintCnt)
		}
	}
	assert.Nil(t, ctx.BecomeCandidate(common.BytesToAddress([]byte("addr"))))
	assert.Nil(t, ctx.SetValidators(validators))
	assert.Nil(t, epochContext.kickOutValidator(testEpoch))
	candidateMap = getCandidates(ctx)
	assert.Equal(t, maxValidatorSize, len(candidateMap))
	assert.False(t, candidateMap[common.BytesToAddress([]byte("addr"+strconv.Itoa(0)))])

	// epochTime is not complete, all validators mint enough block at least
	ctx, err = NewEmptyContext(db)
	assert.Nil(t, err)
	epochContext = &EpochContext{
		TimeStamp: epochInterval / 2,
		Context:   ctx,
		stateDB:   stateDB,
	}
	validators = []common.Address{}
	for i := 0; i < maxValidatorSize; i++ {
		validator := common.BytesToAddress([]byte("addr" + strconv.Itoa(i)))
		validators = append(validators, validator)
		assert.Nil(t, ctx.BecomeCandidate(validator))
		setTestMintCnt(ctx, testEpoch, validator, atLeastMintCnt/2)
	}
	for i := maxValidatorSize; i < maxValidatorSize*2; i++ {
		candidate := common.BytesToAddress([]byte("addr" + strconv.Itoa(i)))
		assert.Nil(t, ctx.BecomeCandidate(candidate))
	}
	assert.Nil(t, ctx.SetValidators(validators))
	assert.Nil(t, epochContext.kickOutValidator(testEpoch))
	candidateMap = getCandidates(ctx)
	assert.Equal(t, maxValidatorSize*2, len(candidateMap))

	// epochTime is not complete, all validators didn't mint enough block at least
	ctx, err = NewEmptyContext(db)
	assert.Nil(t, err)
	epochContext = &EpochContext{
		TimeStamp: epochInterval / 2,
		Context:   ctx,
		stateDB:   stateDB,
	}
	validators = []common.Address{}
	for i := 0; i < maxValidatorSize; i++ {
		validator := common.BytesToAddress([]byte("addr" + strconv.Itoa(i)))
		validators = append(validators, validator)
		assert.Nil(t, ctx.BecomeCandidate(validator))
		setTestMintCnt(ctx, testEpoch, validator, atLeastMintCnt/2-1)
	}
	for i := maxValidatorSize; i < maxValidatorSize*2; i++ {
		candidate := common.BytesToAddress([]byte("addr" + strconv.Itoa(i)))
		assert.Nil(t, ctx.BecomeCandidate(candidate))
	}
	assert.Nil(t, ctx.SetValidators(validators))
	assert.Nil(t, epochContext.kickOutValidator(testEpoch))
	candidateMap = getCandidates(ctx)
	assert.Equal(t, maxValidatorSize, len(candidateMap))

	ctx, err = NewEmptyContext(db)
	assert.Nil(t, err)
	epochContext = &EpochContext{
		TimeStamp: epochInterval / 2,
		Context:   ctx,
		stateDB:   stateDB,
	}
	assert.NotNil(t, epochContext.kickOutValidator(testEpoch))
	ctx.SetValidators([]common.Address{})
	assert.NotNil(t, epochContext.kickOutValidator(testEpoch))
}

func setTestMintCnt(ctx *Context, epoch uint64, validator common.Address, count uint64) {
	for i := uint64(0); i < count; i++ {
		updateMintCnt(epoch*epochInterval, epoch*epochInterval+blockInterval, validator, ctx)
	}
}

func getCandidates(ctx *Context) map[common.Address]bool {
	candidateMap := map[common.Address]bool{}
	iter := ctx.candidateTrie.Iterator(nil)
	for iter.Next() {
		candidateMap[common.BytesToAddress(iter.Value)] = true
	}
	return candidateMap
}

func TestEpochContextTryElect(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	stateDB, _ := state.New(common.Hash{}, state.NewDatabase(db), nil)
	ctx, err := NewEmptyContext(db)
	assert.Nil(t, err)
	epochContext := &EpochContext{
		TimeStamp: epochInterval,
		Context:   ctx,
		stateDB:   stateDB,
	}
	atLeastMintCnt := epochInterval / blockInterval / maxValidatorSize / 2
	testEpoch := uint64(1)
	validators := []common.Address{}
	for i := 0; i < maxValidatorSize; i++ {
		validator := common.BytesToAddress([]byte("addr" + strconv.Itoa(i)))
		validators = append(validators, validator)
		assert.Nil(t, ctx.BecomeCandidate(validator))
		assert.Nil(t, ctx.Delegate(validator, validator))
		stateDB.SetBalance(validator, big.NewInt(1))
		setTestMintCnt(ctx, testEpoch, validator, atLeastMintCnt-1)
	}
	assert.Nil(t, ctx.BecomeCandidate(common.BytesToAddress([]byte("more"))))
	assert.Nil(t, ctx.SetValidators(validators))

	oldHash, err := ctx.Commit()
	assert.Nil(t, err)
	// genesisEpoch == parentEpoch do not kick out
	genesis := &types.Header{
		Time: 0,
	}
	parent := &types.Header{
		Time:       epochInterval - blockInterval,
		EngineInfo: oldHash,
	}
	assert.Nil(t, epochContext.tryElect(genesis, parent))
	result, err := ctx.GetValidators()
	assert.Nil(t, err)
	assert.Equal(t, maxValidatorSize, len(result))
	for _, validator := range result {
		assert.True(t, strings.Contains(string(validator[:]), "addr"))
	}
	assert.NotEqual(t, oldHash, ctx.Info())

	// genesisEpoch != parentEpoch and have none mintCnt do not kickout
	genesis = &types.Header{
		Time: 0,
	}
	parent = &types.Header{
		Difficulty: big.NewInt(1),
		Time:       epochInterval - blockInterval,
	}
	epochContext.TimeStamp = epochInterval
	oldHash = ctx.Info()
	assert.Nil(t, epochContext.tryElect(genesis, parent))
	result, err = ctx.GetValidators()
	assert.Nil(t, err)
	assert.Equal(t, maxValidatorSize, len(result))
	for _, validator := range result {
		assert.True(t, strings.Contains(string(validator.Bytes()), "addr"))
	}
	assert.NotEqual(t, oldHash, ctx.Info())

	// genesisEpoch != parentEpoch kickout
	//genesis = &types.Header{
	//	Time: 0,
	//}
	//parent = &types.Header{
	//	Time: epochInterval*2 - blockInterval,
	//}
	//epochContext.TimeStamp = epochInterval * 2
	//oldHash = ctx.Info()
	//assert.Nil(t, epochContext.tryElect(genesis, parent))
	//result, err = ctx.GetValidators()
	//assert.Nil(t, err)
	//assert.Equal(t, safeSize, len(result))
	//moreCnt := 0
	//for _, validator := range result {
	//	if strings.Contains(string(validator.Bytes()), "more") {
	//		moreCnt++
	//	}
	//}
	//assert.Equal(t, 1, moreCnt)
	//assert.NotEqual(t, oldHash, ctx.Info())

	// parentEpoch == currentEpoch do not elect
	genesis = &types.Header{
		Time: 0,
	}
	parent = &types.Header{
		Time: epochInterval,
	}
	epochContext.TimeStamp = epochInterval + blockInterval
	oldHash, err = ctx.Commit()
	assert.Nil(t, err)
	assert.Nil(t, epochContext.tryElect(genesis, parent))
	result, err = ctx.GetValidators()
	assert.Nil(t, err)
	assert.Equal(t, safeSize, len(result))
	assert.Equal(t, oldHash, ctx.Info())
}
