package evm

import (
	"context"
	"math/big"

	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/vultisig/recipes/common"
)

type Params struct {
	Chain   common.Chain
	AssetID ecommon.Address
	Address ecommon.Address
}

type Provider interface {
	MakeTx(
		ctx context.Context,
		from Params,
		to Params,
		fromAmount *big.Int,
	) (toAmount *big.Int, tx []byte, err error)
}
