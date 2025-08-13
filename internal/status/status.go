package status

import (
	"context"
	"time"

	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/rpc"
)

type Status struct {
	caller rpc.Rpc
}

func NewStatus(caller rpc.Rpc) *Status {
	return &Status{
		caller: caller,
	}
}

func (s *Status) WaitMined(ctx context.Context, txHash string) (rpc.TxOnChainStatus, error) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
			status, err := s.caller.GetTxStatus(ctx, txHash)
			if err != nil {
				return "", err
			}
			if status != rpc.TxOnChainPending {
				return status, nil
			}
		}
	}
}
