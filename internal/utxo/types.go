package utxo

import (
	"context"

	"github.com/btcsuite/btcd/wire"
	"github.com/vultisig/app-recurring/internal/utxo/address"
	"github.com/vultisig/vultisig-go/common"
)

// From represents the source of a UTXO transaction.
type From struct {
	// PubKey is the compressed ECDSA public key (33 bytes).
	// This is chain-agnostic and used for signing.
	PubKey  []byte
	Address address.UTXOAddress
	Amount  uint64
}

// To represents the destination of a UTXO swap.
type To struct {
	Chain   common.Chain
	AssetID string
	Address string
}

// FeeProvider provides fee rate information for a UTXO chain.
type FeeProvider interface {
	SatsPerByte(ctx context.Context) (uint64, error)
}

// SwapProvider provides swap functionality for a UTXO chain.
type SwapProvider interface {
	MakeOutputs(ctx context.Context, from From, to To) (uint64, []*wire.TxOut, error)
	ChangeOutputIndex() int
}

