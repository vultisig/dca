package status

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/rpc"
)

const (
	// WaitMinedTimeout is the maximum time to wait for a transaction to be mined
	// Solana blockhashes are valid for ~60-90 seconds, so we use 90 seconds as timeout
	WaitMinedTimeout = 90 * time.Second
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

	timeout := time.After(WaitMinedTimeout)

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-timeout:
			logrus.WithFields(logrus.Fields{
				"txHash":  txHash,
				"timeout": WaitMinedTimeout.String(),
			}).Warn("WaitMined: timeout waiting for transaction")

			return "", fmt.Errorf("timeout waiting for transaction %s to be mined after %s", txHash, WaitMinedTimeout)
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
