package main

import (
	"encoding/binary"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/harmony"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
	"time"
)

var prefixCandidate = []byte("candidate-")

func newDB(name string) ethdb.Database {
	config := &node.Config{
		Name:    "geth",
		Version: params.Version,
		DataDir: name,
		P2P: p2p.Config{
			ListenAddr:  "0.0.0.0:0",
			NoDiscovery: true,
			MaxPeers:    25,
		},
		UseLightweightKDF: true,
	}
	// Create the node and configure a full Ethereum node on it
	stack, _ := node.New(config)
	engineDB, err := stack.OpenDatabaseWithFreezer("verify", 0, 0, "", "eth/db/chaindata/", false)
	if err != nil {
		log.Error("new engine db error", "err", err)
		return nil
	}
	return engineDB
}

func verifyHarmony(db ethdb.Database) error {
	engineHash := common.HexToHash("0x76596dd2d82a0176f024e40c027df92fd694b7d19a712b8c236e4d3d064f5428")
	ctx, err := harmony.NewContextFromHash(trie.NewDatabase(db), engineHash)
	if err != nil {
		log.Error("new context", "err", err)
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
	iterCandidate := trie.NewIterator(ctx.Trie().PrefixIterator(nil, harmony.CandidatePrefix))
	existCandidate := iterCandidate.Next()
	if !existCandidate {
		log.Error("no candidates")
	}
	return nil
}

func verifyBlock(db ethdb.Database) error {
	block0Hash := common.HexToHash("0x724f1516053543ba1772c3f88c7ce042d511f1a113c0ae03c3f9dbd965d6d484")
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

func main1() {
	db := newDB("lightchaindata")
	if err := verifyBlock(db); err != nil {
		return
	}
	if err := verifyHarmony(db); err != nil {
		return
	}
}

func insert(db ethdb.Database, prefix bool) error {
	ctx, err := harmony.NewContextFromHash(trie.NewDatabase(db), common.Hash{})
	if err != nil {
		log.Error("new context", "err", err)
		return err
	}
	for i := 0; i < 10_000_000; i++ {
		byt := make([]byte, 8)
		binary.BigEndian.PutUint64(byt, uint64(i))
		if !prefix {
			if err := ctx.Trie().TryUpdate(byt, byt); err != nil {
				log.Error("updating", "err", err)
			}
		} else {
			if err := ctx.Trie().TryUpdateWithPrefix(byt, byt, prefixCandidate); err != nil {
				log.Error("updating", "err", err)
			}
		}
	}
	if root, err := ctx.Commit(); err != nil {
		log.Error("committing", "err", err)
		return err
	} else {
		log.Warn("root", "hash", root.String())
	}
	return db.Close()
}

func mainGen() {
	dbPlain := newDB("plain")
	if err := insert(dbPlain, false); err != nil {
		log.Error("-------------")
	}
	dbPrefix := newDB("prefix")
	if err := insert(dbPrefix, true); err != nil {
		log.Error("+++++++++++++")
	}
}

func count(db ethdb.Database, hash string, prefix bool) error {
	engineHash := common.HexToHash(hash)
	ctx, err := harmony.NewContextFromHash(trie.NewDatabase(db), engineHash)
	if err != nil {
		log.Error("new context", "err", err)
		return err
	}
	var it *trie.Iterator
	if prefix {
		it = trie.NewIterator(ctx.Trie().PrefixIterator(nil, prefixCandidate))
	} else {
		it = trie.NewIterator(ctx.Trie().NodeIterator(nil))
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
	dbPlain := newDB("plain")
	t0 := time.Now()
	if err := count(dbPlain, "0x717b6c364a771fb173f7b66b1e5fa7db7891a7ac8a276e6715eb4f4f9e2683bf", false); err != nil {
		log.Error("count", "err", err)
	}
	span0 := time.Now().Sub(t0).Microseconds()
	dbPlain.Close()
	dbPrefix := newDB("prefix")
	t1 := time.Now()
	if err := count(dbPrefix, "0xffd58cc86a961f9db0bd9e5f941daa2cbdaad29c35ad2389887e3e08462c5aee", true); err != nil {
		log.Error("count2", "err", err)
	}
	span1 := time.Now().Sub(t1).Microseconds()
	dbPrefix.Close()
	log.Warn("time cost", "plain", span0, "prefix", span1)
}

func main() {
	mainGen()
	mainCount()
}
