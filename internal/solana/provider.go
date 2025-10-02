package solana

import (
	"context"
	"math/big"

	"github.com/vultisig/vultisig-go/common"
)

type Provider interface {
	MakeTx(ctx context.Context, from From, to To) (*big.Int, []byte, error)
}

type From struct {
	Amount  *big.Int
	AssetID string
	Address string
}

type To struct {
	Chain   common.Chain
	AssetID string
	Address string
}
