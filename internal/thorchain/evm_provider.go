package thorchain

import (
	"context"
	"math/big"

	evm_swap "github.com/vultisig/dca/internal/evm"
)

type EvmProvider struct{}

func NewEvmProvider() *EvmProvider {
	return &EvmProvider{}
}

func (p *EvmProvider) MakeTx(
	ctx context.Context,
	from evm_swap.From,
	to evm_swap.To,
) (*big.Int, []byte, error) {
	return nil, nil, nil
}
