package xrp

import (
	"context"
)

type SwapProvider interface {
	MakeTransaction(ctx context.Context, from From, to To) (txData []byte, toAmount uint64, err error)
}