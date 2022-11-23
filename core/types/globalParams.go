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
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/tidwall/gjson"
	"math/big"
)

type GlobalParams struct {
	FrontierBlockReward   *big.Int "json:frontierBlockReward"   //出块奖励
	ProposalValidEpochCnt uint64   "json:proposalValidEpochCnt" //提案有效期

	//有效提案
	ValidProposals map[string]common.Hash "json:validProposals" //id->hash
	//提案处理后，会移动到无效提案中
	InValidProposals map[string]common.Hash "json:invalidProposals" //id->hash

	ProposalApproves map[string][]common.Address "json:proposalApproves" //id->address

	HashMap map[common.Hash]string "json:hashMap" //hash-uint8 hash map 用途是为了1。快速确定hash是否被处理过 2。快速从hash找到ID

	//记录每个提案对应的epochID
	ProposalEpoch map[string]uint64 "json:proposalEpoch" //id->epoch
}

var (
	ErrCannotFoundParams = errors.New("can not found params to modify")
)

func (g *GlobalParams) InitParams() {
	g.FrontierBlockReward = big.NewInt(5e+18)
	g.ProposalValidEpochCnt = 2

	g.ValidProposals = make(map[string]common.Hash)        //id->hash
	g.ProposalApproves = make(map[string][]common.Address) //id->address

	g.InValidProposals = make(map[string]common.Hash) //id->hash

	g.ProposalEpoch = make(map[string]uint64) //id->epoch
	g.HashMap = make(map[common.Hash]string)
}

func in(target common.Address, str_array []common.Address) bool {
	for _, element := range str_array {
		if target == element {
			return true
		}
	}
	return false
}

func (g *GlobalParams) ApplyProposals(id string, proposalTx *Transaction, threshold int) error {
	//授权是否足够:本次的授权是否大于等于门槛
	if len(g.ProposalApproves[id]) >= threshold {
		log.Info("proposal approved above threshold")
		//todo：应该放在事务中
		//proposalTx中数据应该是参数修改内容--json：string(proposalTx.Data())
		json := string(proposalTx.Data())
		//遍历这个json，依此在全局参数中找到修改
		name := gjson.Parse(json).Get("name")
		value := gjson.Parse(json).Get("value")

		if name.String() == "frontierBlockReward" {
			log.Info("modify params", " name:", name.String(), " value:", value.String())
			g.FrontierBlockReward.SetString(value.String(), 10)

			//将ID在ValidProposals中删除，同时移动到InValidProposals中
			g.InValidProposals[id] = g.ValidProposals[id]
			delete(g.ValidProposals, id)
			return nil
		} else if name.String() == "proposalValidEpochCnt" {
			log.Info("modify params", " name:", name.String(), " value:", value.String())
			g.ProposalValidEpochCnt = uint64(value.Int())

			//将ID在ValidProposals中删除，同时移动到InValidProposals中
			g.InValidProposals[id] = g.ValidProposals[id]
			delete(g.ValidProposals, id)
			return nil
		} else {
			log.Warn("can not found params to modify")
			return ErrCannotFoundParams
		}
	}
	return nil
}
