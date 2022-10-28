package main

import (
	"encoding/binary"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/harmony"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
	"time"
)

var prefixCandidate = []byte("candidate-")

func newDB(dir, name string) ethdb.Database {
	config := &node.Config{
		Name:    "geth",
		Version: params.Version,
		DataDir: dir,
		P2P: p2p.Config{
			ListenAddr:  "0.0.0.0:0",
			NoDiscovery: true,
			MaxPeers:    25,
		},
		UseLightweightKDF: true,
	}
	// Create the node and configure a full Ethereum node on it
	stack, _ := node.New(config)
	engineDB, err := stack.OpenDatabaseWithFreezer(name, 0, 0, "", "eth/db/chaindata/", false)
	if err != nil {
		log.Error("new engine db error", "err", err)
		return nil
	}
	return engineDB
}

func verifyHarmony(db ethdb.Database) error {
	ei := types.EngineInfo{
		EpochHash:     common.HexToHash("0x0a5dfeb3b52a22662b011d6acca0ac65068bde243c3c4215d70ffe4cf2fca999"),
		CandidateHash: common.HexToHash("0x55f025f34d36c18d36964a1e21d3a8ab548bcb24add93319226d65c0ec15a48d"),
		DelegateHash:  common.HexToHash("0xb42c68a9105f934c7d9aba7096498091bef37c9105d3ddfea64fb7a9e9665c68"),
		VoteHash:      common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
		MintCntHash:   common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
	}

	ctx, err := harmony.NewContextFromHash(db, ei)
	if err != nil {
		log.Error("new epochTrie", "err", err)
		return err
	}
	validators, err := ctx.GetValidators()
	if err != nil {
		log.Error("get validators", "err", err)
		return err
	}
	if validators == nil || len(validators) == 0 {
		log.Error("validators length", "err", err)
		return err
	}
	iterCandidate := ctx.CandidateTrie().Iterator(nil)
	existCandidate := iterCandidate.Next()
	if !existCandidate {
		log.Error("no candidates")
	}
	return nil
}

func verifyBlock(db ethdb.Database) error {
	block0Hash := common.HexToHash("0x41ed7f8e879f41dfac8e8bf924ae3eb2cdedf1d6d4de9746f04e7316d64c1bc9")
	block := rawdb.ReadBlock(db, block0Hash, 0)

	if block == nil {
		blockTrie, err := trie.New(common.Hash{}, block0Hash, trie.NewDatabase(db))
		if err != nil {
			log.Error("new block trie error", "err", err)
			return err
		}

		log.Info("block", "block", block)
		iter := trie.NewIterator(blockTrie.NodeIterator(nil))
		exist := iter.Next()
		if !exist {
			log.Error("block is nil")
			return err
		}
		for exist {
			Key := iter.Key
			Value := iter.Value
			log.Info("Commit value", "Key", string(Key), "Value", Value)
			exist = iter.Next()
		}
	}
	return nil
}

func main() {
	db := newDB("feng", "lightchaindata")
	if err := verifyHarmony(db); err != nil {
		return
	}
	if err := verifyBlock(db); err != nil {
		return
	}
}

func insert(db ethdb.Database, prefix bool) error {
	ti, err := harmony.NewTrie(common.Hash{}, trie.NewDatabase(db))
	if err != nil {
		log.Error("new context", "err", err)
		return err
	}
	for i := 0; i < 10_000_000; i++ {
		byt := make([]byte, 8)
		binary.BigEndian.PutUint64(byt, uint64(i))
		if !prefix {
			if err := ti.TryUpdate(byt, byt); err != nil {
				log.Error("updating", "err", err)
			}
		} else {
			if err := ti.TryUpdateWithPrefix(byt, byt, prefixCandidate); err != nil {
				log.Error("updating", "err", err)
			}
		}
	}
	if root, nodes, err := ti.Commit(true); err != nil {
		if nodes != nil {

		}
		log.Error("committing", "err", err)
		return err
	} else {
		log.Warn("root", "hash", root.String())
	}
	return db.Close()
}

func mainGen() {
	dbPlain := newDB("plain", "verify")
	if err := insert(dbPlain, false); err != nil {
		log.Error("-------------")
	}
	dbPrefix := newDB("prefix", "verify")
	if err := insert(dbPrefix, true); err != nil {
		log.Error("+++++++++++++")
	}
}

func count(db ethdb.Database, hash string, prefix bool) error {
	engineHash := common.HexToHash(hash)
	ti, err := harmony.NewTrie(engineHash, trie.NewDatabase(db))
	if err != nil {
		log.Error("new context", "err", err)
		return err
	}
	var it *trie.Iterator
	if prefix {
		it = trie.NewIterator(ti.PrefixIterator(prefixCandidate))
	} else {
		it = trie.NewIterator(ti.NodeIterator(nil))
	}
	count := 0
	for {
		if it.Next() {
			count++
		} else {
			break
		}
	}

	log.Info("count=====", "c", count)
	if count < 10_000_000 {
		return errors.New("less")
	} else {
		return nil
	}
}

func mainCount() {
	dbPlain := newDB("plain", "verify")
	t0 := time.Now()
	if err := count(dbPlain, "0x717b6c364a771fb173f7b66b1e5fa7db7891a7ac8a276e6715eb4f4f9e2683bf", false); err != nil {
		log.Error("count", "err", err)
	}
	span0 := time.Now().Sub(t0).Microseconds()
	dbPlain.Close()
	dbPrefix := newDB("prefix", "verify")
	t1 := time.Now()
	if err := count(dbPrefix, "0xffd58cc86a961f9db0bd9e5f941daa2cbdaad29c35ad2389887e3e08462c5aee", true); err != nil {
		log.Error("count2", "err", err)
	}
	span1 := time.Now().Sub(t1).Microseconds()
	dbPrefix.Close()
	log.Warn("time cost", "plain", span0, "prefix", span1)
}

func mainPrefixVerify() {
	mainGen()
	mainCount()
}
