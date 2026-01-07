package rune

import (
	"context"
)

// SwapProvider interface defines the contract for THORChain swap providers
type SwapProvider interface {
	MakeTransaction(ctx context.Context, from From, to To) (txData []byte, signBytes []byte, toAmount uint64, err error)
}

