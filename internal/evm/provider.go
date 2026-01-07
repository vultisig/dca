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
	Symbol  string
	Address ecommon.Address
	Amount  *big.Int
}

// To destination could be not EVM chain
type To struct {
	Chain   common.Chain
	AssetID string
	Symbol  string
	Address string
}

type Provider interface {
	MakeTx(
		ctx context.Context,
		from From,
		to To,
	) (toAmount *big.Int, tx []byte, err error)
}

// ApprovalProvider is an optional interface for providers that can report
// their approval spender address. The consumer can use this to determine
// the correct spender for token approvals.
type ApprovalProvider interface {
	Provider
	GetApprovalSpender(ctx context.Context, from From, to To) (ecommon.Address, error)
}
