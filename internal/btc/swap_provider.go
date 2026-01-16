package btc

import (
	"context"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/vultisig/app-recurring/internal/utxo/address"
	"github.com/vultisig/vultisig-go/common"
)

type From struct {
	PubKey  *btcutil.AddressPubKey
	Address address.UTXOAddress
	Amount  uint64
}

// To destination could be not BTC chain
type To struct {
	Chain   common.Chain
	AssetID string
	Address string
}

type SwapProvider interface {
	ChangeOutputIndex() int
	MakeOutputs(ctx context.Context, from From, to To) (toAmount uint64, outputs []*wire.TxOut, err error)
}
