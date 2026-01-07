package tron

import (
	"context"
)

// SwapProvider interface defines the contract for TRON swap providers
type SwapProvider interface {
	MakeTransaction(ctx context.Context, from From, to To) (txData []byte, toAmount uint64, err error)
}

