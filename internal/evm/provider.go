package evm

import (
	"context"
	"math/big"

	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/vultisig/vultisig-go/common"
)

type From struct {
	Chain   common.Chain
	AssetID ecommon.Address
	Address ecommon.Address
	Amount  *big.Int
}

// To destination could be not EVM chain
type To struct {
	Chain   common.Chain
	AssetID string
	Address string
}

type Provider interface {
	Name() string
	MakeTx(
		ctx context.Context,
		from From,
		to To,
	) (toAmount *big.Int, tx []byte, err error)
}
