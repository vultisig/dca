package evm

import (
	"context"
	"fmt"
	"math/big"

	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	evmsdk "github.com/vultisig/recipes/sdk/evm"
	"github.com/vultisig/recipes/sdk/evm/codegen/erc20"
)

type balanceService struct {
	rpc *ethclient.Client
}

func newBalanceService(rpc *ethclient.Client) *balanceService {
	return &balanceService{rpc: rpc}
}

func (s *balanceService) GetNativeBalance(ctx context.Context, address ecommon.Address) (*big.Int, error) {
	balance, err := s.rpc.BalanceAt(ctx, address, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get native balance: %w", err)
	}
	return balance, nil
}

func (s *balanceService) GetERC20Balance(ctx context.Context, tokenAddress, ownerAddress ecommon.Address) (*big.Int, error) {
	if tokenAddress == evmsdk.ZeroAddress {
		return s.GetNativeBalance(ctx, ownerAddress)
	}

	erc20Contract := erc20.NewErc20()

	balanceOfData := erc20Contract.PackBalanceOf(ownerAddress)
	balance, err := evmsdk.CallReadonly(
		ctx,
		s.rpc,
		erc20Contract,
		tokenAddress,
		balanceOfData,
		erc20Contract.UnpackBalanceOf,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get ERC20 balance: %w", err)
	}

	return balance, nil
}
