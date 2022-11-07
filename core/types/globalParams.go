// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package types

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"math/big"
)

type GlobalParams struct {
	frontierBlockReward *big.Int
	maxValidatorSize    int

	//有效提案
	validProposals   map[string]common.Hash      //id->hash
	proposalApproves map[string][]common.Address //id->address

	//过期提案
	invalidProsals          map[string]common.Hash      //id->hash
	invalidProposalApproves map[string][]common.Address //id->address
}

func (g *GlobalParams) Init() error {
	g.frontierBlockReward = big.NewInt(5e+18)
	g.maxValidatorSize = 5
	log.Info("..............set globalParams success.............")
	return nil
}

func in(target common.Address, str_array []common.Address) bool {
	for _, element := range str_array {
		if target == element {
			return true
		}
	}
	return false
}

func (g *GlobalParams) ApplyProposals(txs []*Transaction, validators []common.Address) string {
	id := ""
	for _, tx := range txs {
		if tx.Type() == ProposalTxType {
			//首先看该提案在全局参数中是否存在：应该是tx 数据中的提案编号
			exist := false
			//遍历map找到key

			for key, value := range g.validProposals {
				if value == tx.Hash() { //这里错误
					exist = true
					id = key
				}
			}
			if exist { //有效提案，看获得的授权是否足够
				threshold := g.maxValidatorSize/2 + 1

				var from common.Address //tx的from地址
				//授权是否足够，比对两个因素:1.当前签名者是否是见证人 2.加上本次的授权是否大于等于门槛
				result := in(from, validators)
				if result == true {
					if len(g.proposalApproves[id])+1 >= threshold {
						//todo：应该放在事务中
						g.proposalApproves[id] = append(g.proposalApproves[id], from)
						//todo：怎么知道修改的是什么东西？id->
					}
				} else {

				}

			} else {
				log.Info("++++++++got ProposalTx++++++")
				len := len(g.validProposals)
				id = fmt.Sprintf("%s.%d", params.Version, len+1)
				g.validProposals[id] = tx.Hash()
			}
		}
	}
	return id
}

func (g *GlobalParams) StoreParamsToDisk() error {
	return nil
}

func (g *GlobalParams) GetProposalID(hash common.Hash) error {
	return nil
}

func (g *GlobalParams) ReadParamsFromDisk() error {
	return nil
}
