package harmony

import (
	"encoding/binary"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/stretchr/testify/assert"
)

var (
	MockEpoch = []string{
		"0x44d1ce0b7cb3588bca96151fe1bc05af38f91b6e",
		"0xa60a3886b552ff9992cfcd208ec1152079e046c2",
		"0x4e080e49f62694554871e669aeb4ebe17c4a9670",
		"0xb040353ec0f2c113d5639444f7253681aecda1f8",
		"0x14432e15f21237013017fa6ee90fc99433dec82c",
		"0x9f30d0e5c9c88cade54cd1adecf6bc2c7e0e5af6",
		"0xd83b44a3719720ec54cdb9f54c0202de68f1ebcb",
		"0x56cc452e450551b7b9cffe25084a069e8c1e9441",
		"0xbcfcb3fa8250be4f2bf2b1e70e1da500c668377b",
		"0x9d9667c71bb09d6ca7c3ed12bfe5e7be24e2ffe1",
		"0xabde197e97398864ba74511f02832726edad5967",
		"0x6f99d97a394fa7a623fdf84fdc7446b99c3cb335",
		"0xf78b011e639ce6d8b76f97712118f3fe4a12dd95",
		"0x8db3b6c801dddd624d6ddc2088aa64b5a2493661",
		"0x751b484bd5296f8d267a8537d33f25a848f7f7af",
		"0x646ba1fa42eb940aac67103a71e9a908ef484ec3",
		"0x34d4a8d9f6b53a8f5e674516cb8ad66c843b2801",
		"0x5b76fff970bf8a351c1c9ebfb5e5a9493e956ddd",
		"0x8da3c5aedaf106c61cfee6d8483e1f255fdd60c0",
		"0x2cdbe87a1bd7ee60dd6fe97f7b2d1efbacd5d95d",
		"0x743415d0e979dc6e426bc8189e40beb65bf5ac1d",
	}
)

func mockNewContext(db *trie.Database) *Context {
	ctx, err := NewContextFromHash(db, common.Hash{})
	if err != nil {
		return nil
	}
	delegator := []byte{}
	candidate := []byte{}
	addresses := []common.Address{}
	for i := 0; i < maxValidatorSize; i++ {
		addresses = append(addresses, common.HexToAddress(MockEpoch[i]))
	}
	ctx.SetValidators(addresses)
	for j := 0; j < len(MockEpoch); j++ {
		delegator = common.HexToAddress(MockEpoch[j]).Bytes()
		candidate = common.HexToAddress(MockEpoch[j]).Bytes()
		ctx.trie.TryUpdateWithPrefix(append(candidate, delegator...), candidate, DelegatePrefix)
		ctx.trie.TryUpdateWithPrefix(candidate, candidate, CandidatePrefix)
		ctx.trie.TryUpdateWithPrefix(candidate, candidate, votePrefix)
	}
	return ctx
}

func setMintCntTrie(epochID uint64, candidate common.Address, mintCntTrie *trie.Trie, count int64) {
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, uint64(epochID))
	cntBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(cntBytes, uint64(count))
	mintCntTrie.TryUpdateWithPrefix(append(key, candidate.Bytes()...), cntBytes, mintCntPrefix)
}

func getMintCnt(epochID uint64, candidate common.Address, mintCntTrie *trie.Trie) int64 {
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, epochID)
	cntBytes, err := mintCntTrie.TryGetWithPrefix(append(key, candidate.Bytes()...), mintCntPrefix)
	if cntBytes == nil || err != nil {
		return 0
	} else {
		return int64(binary.BigEndian.Uint64(cntBytes))
	}
}

func TestUpdateMintCnt(t *testing.T) {
	db := trie.NewDatabase(rawdb.NewMemoryDatabase())
	ctx := mockNewContext(db)

	// new block still in the same epoch with current block, but newMiner is the first time to mint in the epoch
	lastTime := epochInterval

	miner := common.HexToAddress("0xa60a3886b552ff9992cfcd208ec1152079e046c2")
	blockTime := epochInterval + blockInterval

	beforeUpdateCnt := getMintCnt(blockTime/epochInterval, miner, ctx.trie)
	updateMintCnt(lastTime, blockTime, miner, ctx)
	afterUpdateCnt := getMintCnt(blockTime/epochInterval, miner, ctx.trie)
	assert.Equal(t, int64(0), beforeUpdateCnt)
	assert.Equal(t, int64(1), afterUpdateCnt)

	// new block still in the same epoch with current block, and newMiner has mint block before in the epoch
	setMintCntTrie(blockTime/epochInterval, miner, ctx.trie, int64(1))

	blockTime = epochInterval + blockInterval*4

	// currentBlock has recorded the count for the newMiner before UpdateMintCnt
	beforeUpdateCnt = getMintCnt(blockTime/epochInterval, miner, ctx.trie)
	updateMintCnt(lastTime, blockTime, miner, ctx)
	afterUpdateCnt = getMintCnt(blockTime/epochInterval, miner, ctx.trie)
	assert.Equal(t, int64(1), beforeUpdateCnt)
	assert.Equal(t, int64(2), afterUpdateCnt)

	// new block come to a new epoch
	blockTime = epochInterval * 2

	beforeUpdateCnt = getMintCnt(blockTime/epochInterval, miner, ctx.trie)
	updateMintCnt(lastTime, blockTime, miner, ctx)
	afterUpdateCnt = getMintCnt(blockTime/epochInterval, miner, ctx.trie)
	assert.Equal(t, int64(0), beforeUpdateCnt)
	assert.Equal(t, int64(1), afterUpdateCnt)
}
