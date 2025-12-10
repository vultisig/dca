package evm

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/vultisig/recipes/sdk/evm"
	"github.com/vultisig/recipes/sdk/evm/codegen/erc20"
)

type decimalsService struct {
	rpc *ethclient.Client
}

func newDecimalsService(rpc *ethclient.Client) *decimalsService {
	return &decimalsService{
		rpc: rpc,
	}
}

// GetDecimals fetches the decimals for an ERC20 token
func (d *decimalsService) GetDecimals(ctx context.Context, tokenAddress common.Address) (uint8, error) {
	var zero common.Address
	if tokenAddress == zero {
		return 0, fmt.Errorf("token address cannot be zero")
	}

	erc20Contract := erc20.NewErc20()

	decimalsData := erc20Contract.PackDecimals()
	decimals, err := evm.CallReadonly(
		ctx,
		d.rpc,
		erc20Contract,
		tokenAddress,
		decimalsData,
		erc20Contract.UnpackDecimals,
		nil,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to get decimals for token %s: %w", tokenAddress.Hex(), err)
	}

	return decimals, nil
}
