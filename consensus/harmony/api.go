// Copyright 2017 The go-ethereum Authors
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

package harmony

import (
	"encoding/binary"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"
)

// API is a user facing RPC API to allow controlling the delegate and voting
// mechanisms of the delegated-proof-of-stake
type API struct {
	chain  consensus.ChainHeaderReader
	engine *Harmony
}

// MintKeyLen -> mint trie 的key 长度
const MintKeyLen = 36

// GetValidators retrieves the list of the validators at specified block
func (api *API) GetValidators(number *rpc.BlockNumber) ([]common.Address, error) {
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	if header == nil {
		return nil, errUnknownBlock
	}

	ctxTrie, err := newEpochTrie(header.EngineInfo.EpochHash, api.engine.db)
	if err != nil {
		return nil, err
	}
	ctx := Context{}
	ctx.SetEpochTrie(ctxTrie)
	validators, err := ctx.GetValidators()
	if err != nil {
		return nil, err
	}
	return validators, nil
}

// GetConfirmedBlockNumber retrieves the latest irreversible block
func (api *API) GetConfirmedBlockNumber() (*big.Int, error) {
	var err error
	header := api.engine.confirmedBlockHeader
	if header == nil {
		header, err = api.engine.loadConfirmedBlockHeader(api.chain)
		if err != nil {
			return nil, err
		}
	}
	return header.Number, nil
}

// GetDelegateList retrieves DelegateTrie for canlidates and its Delegate
// DelegateTrie数据格式：
// key：delegate-候选人地址-投票人地址
// value：投票人地址
func (api *API) GetDelegateList() (map[common.Address]common.Address, error) {
	delegates := map[common.Address]common.Address{}

	var header *types.Header

	header = api.chain.CurrentHeader()

	if header == nil {
		return nil, errUnknownBlock
	}

	ctxTrie, err := newDelegateTrie(header.EngineInfo.DelegateHash, api.engine.db)
	if err != nil {
		return nil, err
	}

	iterDelegate := ctxTrie.Iterator(nil)
	existDelegate := iterDelegate.Next()
	if !existDelegate {
		//return delegates, errors.New("no delegates")
	}
	for existDelegate {
		addr := iterDelegate.Key
		candidate := iterDelegate.Value
		delegates[common.BytesToAddress(addr)] = common.BytesToAddress(candidate)
		existDelegate = iterDelegate.Next()
	}
	return delegates, nil
}

// GetVoteList retrieves voteTrie return Delegate and its vote guy
// VoteTrie数据格式：
// key：vote-投票人地址
// value：候选人地址
func (api *API) GetVoteList(number *rpc.BlockNumber) (map[common.Address]common.Address, error) {
	candidates := map[common.Address]common.Address{}

	var header *types.Header

	header = api.chain.CurrentHeader()

	if header == nil {
		return nil, errUnknownBlock
	}

	voteTrie, err := newVoteTrie(header.EngineInfo.VoteHash, api.engine.db)
	if err != nil {
		return nil, err
	}

	iterCandidate := voteTrie.Iterator(nil)
	existCandidate := iterCandidate.Next()
	if !existCandidate {
		//return votes, errors.New("no candidates")
	}
	if existCandidate {
		addr := iterCandidate.Key
		candidate := iterCandidate.Value
		candidates[common.BytesToAddress(addr)] = common.BytesToAddress(candidate)
	}
	return candidates, nil
}

// GetMintCnt 得到epoch的所有验证节点和对应的出块数
// MintCntTrie数据格式：
// key；mintCnt-周期数（2进制）-验证人
// value：当前验证人本周期总共挖块数
func (api *API) GetMintCnt(epochID int) (map[common.Address]uint64, error) {
	mintMap := map[common.Address]uint64{}

	var header *types.Header

	header = api.chain.CurrentHeader()

	if header == nil {
		return nil, errUnknownBlock
	}

	mintTrie, err := newMintTrie(header.EngineInfo.MintCntHash, api.engine.db)
	if err != nil {
		return nil, err
	}

	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, uint64(epochID))

	iterMint := mintTrie.Iterator(key)
	existMint := iterMint.Next()
	if !existMint {
		//return nil, errors.New("no candidates")
	}
	for existMint {
		key := iterMint.Key
		value := iterMint.Value

		if len(key) != MintKeyLen {
			log.Info("existMint len is not expected", "key", MintKeyLen)
		}
		//key 0-7 前缀 8-15 epoch 16-35 validator addr
		validator := common.BytesToAddress(key[15:36])

		epoch := binary.BigEndian.Uint64(key[8:16])
		cnt := binary.BigEndian.Uint64(value)

		log.Info("votes", "epoch", epoch, "validator", validator, "value", cnt)

		mintMap[validator] = cnt
		existMint = iterMint.Next()
	}

	return mintMap, nil
}

// GetValidatorMintCnt --- 得到epoch中validator的出块数
// MintCntTrie数据格式：
// key；mintCnt-周期数（2进制）-验证人
// value：当前验证人本周期总共挖块数
func (api *API) GetValidatorMintCnt(epochID int, addr string) (uint64, error) {
	count := uint64(0)
	var header *types.Header

	header = api.chain.CurrentHeader()

	if header == nil {
		return 0, errUnknownBlock
	}

	mintTrie, err := newMintTrie(header.EngineInfo.MintCntHash, api.engine.db)
	if err != nil {
		return 0, err
	}

	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, uint64(epochID))
	validator := common.HexToAddress(addr)

	cntBytes, err := mintTrie.t.TryGet(append(key, validator.Bytes()...))
	if cntBytes != nil {
		count = binary.BigEndian.Uint64(cntBytes)
	}

	return count, err
}

// GetCandidates retrieves current candidates
func (api *API) GetCandidates() ([]common.Address, error) {
	//var header *types.Header
	//var candidates []common.Address
	//header = api.chain.CurrentHeader()
	//
	//if header == nil {
	//	return nil, errUnknownBlock
	//}
	//
	//candidateTrie, err := newCandidateTrie(header.EngineInfo.CandidateHash, api.engine.db)
	//if err != nil {
	//	return nil, err
	//}
	//iterCandidates := candidateTrie.t.NodeIterator(nil)
	//existCandidate := iterCandidates.Next(true)
	//if !existCandidate {
	//	//return nil, errors.New("no candidates")
	//}
	//for existCandidate {
	//	addr1 := iterCandidates.
	//	addr2 := iterCandidates.Value
	//	if bytes.Equal(addr2, addr1) {
	//
	//	}
	//	candidates = append(candidates, common.BytesToAddress(addr2))
	//	existCandidate = iterCandidates.Next()
	//}
	//return candidates, nil

	//遍历测试
	b, err := api.engine.ctx.candidateTrie.t.TryGet(common.HexToAddress("0x03796c32df43e1138946845f63c641be3b5f8570").Bytes())
	if err != nil {
		log.Info("++++++++++error++++++++++++: ")
	}
	log.Info("+++++++++canlidates+++++++++++: ", common.BytesToAddress(b).Hex())
	return nil, nil
}
