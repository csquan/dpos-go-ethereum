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
	"encoding/json"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/tidwall/gjson"
	"io/ioutil"
	"math/big"
	"os"
)

type GlobalParams struct {
	FrontierBlockReward   *big.Int //出块奖励
	MaxValidatorSize      int      //见证人数量--目前没找到在哪里生效
	ProposalValidEpochCnt uint64   //提案有效期

	//有效提案
	ValidProposals   map[string]common.Hash      //id->hash
	ProposalApproves map[string][]common.Address //id->address

	HashMap map[common.Hash]uint8 //hash-uint8 hash map 用途是为了快速确定hash是否被处理过

	//记录每个提案对应的epochID
	ProposalEpoch map[string]uint64 //id->epoch
}

var (
	ErrCannotFoundParams          = errors.New("can not found params to modify")
	ErrMintFutureBlock            = errors.New("mint the future block")
	ErrMismatchSignerAndValidator = errors.New("mismatch block signer and validator")
	ErrInvalidBlockValidator      = errors.New("not my turn")
	ErrInvalidMintBlockTime       = errors.New("not mining time")
	ErrNilBlockHeader             = errors.New("nil block header returned")
)

func (g *GlobalParams) initParams() {
	g.FrontierBlockReward = big.NewInt(5e+18)
	g.MaxValidatorSize = 1
	g.ProposalValidEpochCnt = 2

	g.ValidProposals = make(map[string]common.Hash)        //id->hash
	g.ProposalApproves = make(map[string][]common.Address) //id->address

	g.ProposalEpoch = make(map[string]uint64) //id->epoch

	g.HashMap = make(map[common.Hash]uint8)
}
func (g *GlobalParams) Init() error {
	//ReadParamsFromDisk
	err := g.ReadParamsFromDisk()
	if err != nil { //没找到文件，说明是第一次启动
		log.Info("..............init globalParams .............")
		g.initParams()
	} else {
		log.Info("..............read globalParams .............")
	}

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

func (g *GlobalParams) ApplyProposals(tx *Transaction, proposalTx *Transaction) error {
	//首先应该找到交易内容--提案ID，该提案在全局参数中是否存在：应该是tx 数据中的提案编号
	id := string(tx.inner.data())

	threshold := g.MaxValidatorSize/2 + 1

	//授权是否足够:本次的授权是否大于等于门槛
	if len(g.ProposalApproves[id]) >= threshold {
		log.Warn("proposal approved above threshold")
		//todo：应该放在事务中
		//proposalTx中数据应该是参数修改内容--json：string(proposalTx.Data())
		json := string(proposalTx.Data())
		//遍历这个json，依此在全局参数中找到修改
		name := gjson.Parse(json).Get("name")
		value := gjson.Parse(json).Get("value")

		if name.String() == "frontierBlockReward" {
			log.Warn("modify params", " name:", name.String(), " value:", value.String())
			g.FrontierBlockReward.SetString(value.String(), 10)
		} else {
			log.Warn("can not found params to modify")
			return ErrCannotFoundParams
		}
	}
	return nil
}

func (g *GlobalParams) StoreParamsToDisk() error {
	file, err := os.OpenFile("./globalParams", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := json.Marshal(&g)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	return nil
}

func (g *GlobalParams) ReadParamsFromDisk() error {
	file, err := os.Open("./globalParams")
	if err != nil {
		return err
	}
	defer file.Close()
	//g===>[]byte
	content, err := ioutil.ReadAll(file)

	str := string(content)

	var gp GlobalParams
	gp.initParams()
	err = json.Unmarshal([]byte(str), gp)
	if err != nil {
		return err
	}
	g = &gp
	return nil
}
