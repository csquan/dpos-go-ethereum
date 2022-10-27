package main

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/harmony"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
)

func newDB() ethdb.Database {
	config := &node.Config{
		Name:    "geth",
		Version: params.Version,
		DataDir: "feng",
		P2P: p2p.Config{
			ListenAddr:  "0.0.0.0:0",
			NoDiscovery: true,
			MaxPeers:    25,
		},
		UseLightweightKDF: true,
	}
	// Create the node and configure a full Ethereum node on it
	stack, _ := node.New(config)
	engineDB, err := stack.OpenDatabaseWithFreezer("lightchaindata", 0, 0, "", "eth/db/chaindata/", false)
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

func main() {
	db := newDB()
	if err := verifyBlock(db); err != nil {
		return
	}
	if err := verifyHarmony(db); err != nil {
		return
	}
}
