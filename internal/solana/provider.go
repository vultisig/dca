package solana

import (
	"context"
	"math/big"

	"github.com/vultisig/vultisig-go/common"
)

type Provider interface {
	// CheckSetup checks if setup transactions are needed for the swap
	CheckSetup(ctx context.Context, from From, to To) (bool, error)

	// BuildSetupTxs builds setup transactions that must be executed before the swap
	BuildSetupTxs(ctx context.Context, from From, to To) ([][]byte, error)

	// MakeTx builds the swap transaction
	MakeTx(ctx context.Context, from From, to To) (*big.Int, []byte, error)

	// CheckCleanup checks if cleanup transactions are needed after the swap
	CheckCleanup(ctx context.Context, from From, to To) (bool, error)

	// BuildCleanupTxs builds cleanup transactions that must be executed after the swap
	BuildCleanupTxs(ctx context.Context, from From, to To) ([][]byte, error)
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
