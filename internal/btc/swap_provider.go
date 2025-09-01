package btc

import (
	"context"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/vultisig/vultisig-go/common"
)

type From struct {
	Address btcutil.Address
	Amount  uint64
}

type To struct {
	Chain   common.Chain
	Address string
}

type swapProvider interface {
	ChangeOutputIndex() int
	MakeOutputs(ctx context.Context, from From, to To) (toAmount uint64, outputs []*wire.TxOut, err error)
}
