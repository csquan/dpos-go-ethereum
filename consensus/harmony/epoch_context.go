package harmony

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"math/big"
	"math/rand"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
)

var globalParamsKey = []byte("hui chan global params")

type EpochContext struct {
	TimeStamp uint64
	Context   *Context
	stateDB   *state.StateDB
}

var (
	epochInterval = uint64(600)
	blockInterval = 2
)

// countVotes
func (ec *EpochContext) countVotes() (votes map[common.Address]*big.Int, err error) {
	votes = map[common.Address]*big.Int{}
	delegateTrie := ec.Context.delegateTrie
	candidateTrie := ec.Context.candidateTrie

	iterCandidate := candidateTrie.Iterator(nil)
	existCandidate := iterCandidate.Next()
	if !existCandidate {
		return votes, errors.New("no candidates")
	}
	for existCandidate {
		candidate := iterCandidate.Value
		candidateAddr := common.BytesToAddress(candidate)
		delegateIterator := delegateTrie.Iterator(candidate)
		existDelegator := delegateIterator.Next()
		if !existDelegator {
			votes[candidateAddr] = new(big.Int)
			existCandidate = iterCandidate.Next()
			continue
		}
		for existDelegator {
			delegator := delegateIterator.Value
			score, ok := votes[candidateAddr]
			if !ok {
				score = new(big.Int)
			}
			delegatorAddr := common.BytesToAddress(delegator)
			weight := ec.stateDB.GetBalance(delegatorAddr)
			score.Add(score, weight)
			votes[candidateAddr] = score
			existDelegator = delegateIterator.Next()
		}
		existCandidate = iterCandidate.Next()
	}
	log.Info("*******in epoch get vote*********")
	for k, v := range votes {
		log.Info("votes", "key", k.String(), "value", v)
	}
	return votes, nil
}

func (ec *EpochContext) kickOutValidator(epoch uint64) error {
	validators, err := ec.Context.GetValidators()
	if err != nil {
		return fmt.Errorf("failed to get validator: %s", err)
	}
	if len(validators) == 0 {
		return errors.New("no validator could be kickout")
	}

	epochDuration := epochInterval
	// First epoch duration may lt epoch interval,
	// while the first block time wouldn't always align with epoch interval,
	// so calculate the first epoch duration with first block time instead of epoch interval,
	// prevent the validators were kick-out incorrectly.
	if ec.TimeStamp-timeOfFirstBlock < epochInterval {
		epochDuration = ec.TimeStamp - timeOfFirstBlock
	}

	needKickOutValidators := sortableAddresses{}
	for _, validator := range validators {
		key := make([]byte, 8)
		binary.BigEndian.PutUint64(key, epoch)
		key = append(key, validator.Bytes()...)
		cnt := uint64(0)
		if cntBytes, err := ec.Context.mintCntTrie.t.TryGet(key); err == nil && cntBytes != nil {
			cnt = binary.BigEndian.Uint64(cntBytes)
		}
		//@keep, remove compile error
		if cnt < epochDuration/uint64(blockInterval)/maxValidatorSize/2 {
			// not active validators need kick out
			needKickOutValidators = append(needKickOutValidators, &sortableAddress{validator, big.NewInt(int64(cnt))})
		}
	}
	// no validators need kick out
	needKickOutValidatorCnt := len(needKickOutValidators)
	if needKickOutValidatorCnt <= 0 {
		return nil
	}
	sort.Sort(sort.Reverse(needKickOutValidators))

	candidateCount := 0
	iter := ec.Context.candidateTrie.Iterator(nil)
	for iter.Next() {
		candidateCount++
		if candidateCount >= needKickOutValidatorCnt+safeSize {
			break
		}
	}

	for i, validator := range needKickOutValidators {
		// ensure candidate count greater than or equal to safeSize
		if candidateCount <= safeSize {
			log.Info("No more candidate can be kickout", "prevEpochID", epoch, "candidateCount", candidateCount, "needKickoutCount", len(needKickOutValidators)-i)
			return nil
		}

		if err := ec.Context.KickOutCandidate(validator.address); err != nil {
			return err
		}
		// if kick-out success, candidateCount minus 1
		candidateCount--
		log.Info("Kickout candidate", "prevEpochID", epoch, "candidate", validator.address.String(), "mintCnt", validator.weight.String())
	}
	return nil
}

func (ec *EpochContext) lookupValidator(now uint64) (validator common.Address, err error) {
	offset := now % epochInterval
	if offset%uint64(blockInterval) != 0 {
		return common.Address{}, ErrInvalidMintBlockTime
	}
	offset /= uint64(blockInterval)

	validators, err := ec.Context.GetValidators()
	if err != nil {
		return common.Address{}, err
	}
	validatorSize := len(validators)
	if validatorSize == 0 {
		return common.Address{}, errors.New("failed to lookup validator")
	}
	offset %= uint64(validatorSize)
	return validators[offset], nil
}

func (ec *EpochContext) tryElect(genesis, parent *types.Header, h *Harmony) error {
	genesisEpoch := genesis.Time / epochInterval
	prevEpoch := parent.Time / epochInterval
	currentEpoch := ec.TimeStamp / epochInterval

	prevEpochIsGenesis := prevEpoch == genesisEpoch
	if prevEpochIsGenesis && prevEpoch < currentEpoch {
		prevEpoch = currentEpoch - 1
	}

	if err := ec.Context.RefreshFromHash(parent.EngineInfo); err != nil {
		return err
	}
	prevEpochBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(prevEpochBytes, prevEpoch)
	iter := ec.Context.mintCntTrie.Iterator(prevEpochBytes)
	for i := prevEpoch; i < currentEpoch; i++ {
		approveProposal(h, currentEpoch)
		// if prevEpoch is not genesis, kick-out candidates not active
		if !prevEpochIsGenesis && iter.Next() {
			if err := ec.kickOutValidator(prevEpoch); err != nil {
				return err
			}
		}
		votes, err := ec.countVotes()
		if err != nil {
			return err
		}
		candidates := sortableAddresses{}
		for candidate, cnt := range votes {
			candidates = append(candidates, &sortableAddress{candidate, cnt})
		}
		if len(candidates) < safeSize {
			return errors.New("too few candidates")
		}
		sort.Sort(candidates)
		if len(candidates) > maxValidatorSize {
			candidates = candidates[:maxValidatorSize]
		}

		// shuffle candidates
		seed := binary.LittleEndian.Uint64(crypto.Keccak512(parent.Hash().Bytes())) + i
		r := rand.New(rand.NewSource(int64(seed)))
		for i := len(candidates) - 1; i > 0; i-- {
			j := int(r.Int31n(int32(i + 1)))
			candidates[i], candidates[j] = candidates[j], candidates[i]
		}
		sortedValidators := make([]common.Address, 0)
		for _, candidate := range candidates {
			sortedValidators = append(sortedValidators, candidate.address)
		}
		if err = ec.Context.SetValidators(sortedValidators); err != nil {
			log.Warn("set new validators", "err", err)
		}

		if err = ec.Context.SetValidatorsInEpoch(sortedValidators, epochNumber); err != nil {
			//TODO
		}

		log.Info("Come to new epoch", "prevEpoch", i, "nextEpoch", i+1)
	}
	return nil
}
func GetTransaction(db ethdb.Database, hash common.Hash) *types.Transaction {
	tx, _, _, _ := rawdb.ReadTransaction(db, hash)
	if tx == nil {
		return nil
	}
	return tx
}

// 遍历授权列表--如果提案没有过期，则调用globalParams.ApplyProposals
func approveProposal(engine *Harmony, currentEpoch uint64) error {
	globalParams, err := getParams(engine)
	if err != nil {
		return err
	}

	for id, _ := range globalParams.ValidProposals {
		validCnt := globalParams.ProposalValidEpochCnt

		if currentEpoch <= globalParams.ProposalEpoch[id]+validCnt+1 { // 查看当前id是否过期
			hash := globalParams.ValidProposals[id]

			proposalTx := GetTransaction(engine.db, hash)
			if proposalTx == nil {
				log.Info("In approveProposal", "can not find tx of hash:", hash)
				continue
			}
			validators, err := engine.Ctx().GetValidators() // 实时得到当前的见证人
			if err != nil {
				return fmt.Errorf("failed to get validator: %s", err)
			}
			threshold := len(validators)/2 + 1 // 这里门槛的设置需要再考虑
			err = globalParams.ApplyProposals(id, proposalTx, threshold)
			if err == nil { // 表示执行成功
				data, err := json.Marshal(globalParams)
				if err != nil {
					return err
				}
				// 写回rawdb
				rawdb.WriteParams(engine.GetDB(), globalParamsKey, data)
			}
			if currentEpoch == globalParams.ProposalEpoch[id]+validCnt+1 { // 移动到invalid-确保没有足够授权，但是到了最后截止日子能移动到invalid
				// 过期了-移动id到invalid中
				// 将ID在ValidProposals中删除，同时移动到InValidProposals中
				globalParams.InValidProposals[id] = globalParams.ValidProposals[id]
				delete(globalParams.ValidProposals, id)

				data, err := json.Marshal(globalParams)
				if err != nil {
					return err
				}
				// 写回rawdb
				rawdb.WriteParams(engine.GetDB(), globalParamsKey, data)
			}
		}
	}
	return nil
}

func getParams(engine *Harmony) (types.GlobalParams, error) {
	globalParams := types.GlobalParams{}
	g := rawdb.ReadParams(engine.GetDB())

	err := json.Unmarshal(g, &globalParams)
	if err != nil {
		log.Error("Unmarshal,", "err", err)
	}
	return globalParams, err

}

type sortableAddress struct {
	address common.Address
	weight  *big.Int
}
type sortableAddresses []*sortableAddress

func (p sortableAddresses) Swap(i, j int) { p[i], p[j] = p[j], p[i] }
func (p sortableAddresses) Len() int      { return len(p) }
func (p sortableAddresses) Less(i, j int) bool {
	if p[i].weight.Cmp(p[j].weight) < 0 {
		return false
	} else if p[i].weight.Cmp(p[j].weight) > 0 {
		return true
	} else {
		return p[i].address.String() < p[j].address.String()
	}
}
