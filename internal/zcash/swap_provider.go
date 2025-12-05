package zcash

import (
	"context"
)

// TxOutput represents a transaction output for Zcash
type TxOutput struct {
	Value   int64
	Script  []byte
	Address string // For reference/debugging
}

type SwapProvider interface {
	ChangeOutputIndex() int
	MakeOutputs(ctx context.Context, from From, to To) (toAmount uint64, outputs []*TxOutput, err error)
}
