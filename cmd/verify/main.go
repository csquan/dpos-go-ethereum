package main

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/harmony"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/trie"
)

func main() {
	engineDB := harmony.OpenDB()
	engineHashHex := "0x19f03c91c02df66f8398c02d933d3c0bd31cd3dfed4e3c35f34a5dd02fa88565"
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
