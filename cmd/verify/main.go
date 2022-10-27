package main

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/harmony"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
)

func main() {
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
	stack, err := node.New(config)
	engineDB, err := stack.OpenDatabaseWithFreezer("chaindata", 1, 1, "", "eth/db/chaindata/", false)
	engineHashHex := "0x76596dd2d82a0176f024e40c027df92fd694b7d19a712b8c236e4d3d064f5428"
	ctx, err := harmony.NewContextFromHash(trie.NewDatabase(engineDB), common.HexToHash(engineHashHex))
	if err != nil {
		log.Error("new context", "err", err)
	}
	validators, err := ctx.GetValidators()
	if err != nil {
		log.Error("new context", "err", err)
	}
	if len(validators) != 6 {
		log.Error("new context", "err", err)
	}
}
