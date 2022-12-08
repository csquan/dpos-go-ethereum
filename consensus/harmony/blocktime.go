package harmony

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"math/rand"
)

// @keep, 本节点出块的时间。
func (h *Harmony) blockTime(snap *Snapshot, parent *types.Header) uint64 {
	blockTime := parent.Time + h.config.Period + backOffTime(snap, h.signer)
	return blockTime
}

// @keep，如果header的时间 - parent.Time的时间 小于 该validator backOff的时间，返回错误。
func (h *Harmony) verifyBlockTime(snap *Snapshot, header, parent *types.Header) error {
	if header.Time < parent.Time+h.config.Period+backOffTime(snap, header.Coinbase) {
		return errInvalidTimestamp
	}
	return nil
}

// @keep, 计算validator 出块的延迟，避免出现同时出块撞车
// 如果是intrurn 不需要delay，否则随机delay一个时间，并且各个validator delay的时间不一致。
func backOffTime(snap *Snapshot, signer common.Address) uint64 {
	if snap.inturn(snap.Number+1, signer) {
		return 0
	} else {
		idx := snap.indexOfSigner(signer)
		if idx < 0 {
			// The backOffTime does not matter when a validator is not authorized.
			return 0
		}
		s := rand.NewSource(int64(snap.Number))
		r := rand.New(s)
		n := len(snap.signers())
		backOffSteps := make([]uint64, 0, n) //backOff步长，即每一个validator
		for idx := uint64(0); idx < uint64(n); idx++ {
			backOffSteps = append(backOffSteps, idx)
		}
		r.Shuffle(n, func(i, j int) {
			backOffSteps[i], backOffSteps[j] = backOffSteps[j], backOffSteps[i]
		})
		delay := initialBackOffTime + backOffSteps[idx]*wiggleTime
		return delay
	}
}
