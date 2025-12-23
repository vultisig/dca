package evm

import (
	"context"
	"fmt"
	"math/big"

	ecommon "github.com/ethereum/go-ethereum/common"
	evmsdk "github.com/vultisig/recipes/sdk/evm"
)

type sendService struct {
	sdk *evmsdk.SDK
}

func newSendService(sdk *evmsdk.SDK) *sendService {
	return &sendService{
		sdk: sdk,
	}
}

func (s *sendService) BuildNativeTransfer(
	ctx context.Context,
	from ecommon.Address,
	to ecommon.Address,
	amount *big.Int,
	nonceOffset uint64,
) ([]byte, error) {
	tx, err := s.sdk.MakeTxTransferNative(ctx, from, to, amount, nonceOffset)
	if err != nil {
		return nil, fmt.Errorf("failed to make native transfer tx: %w", err)
	}

	return tx, nil
}

func (s *sendService) BuildERC20Transfer(
	ctx context.Context,
	token ecommon.Address,
	from ecommon.Address,
	to ecommon.Address,
	amount *big.Int,
	nonceOffset uint64,
) ([]byte, error) {
	tx, err := s.sdk.MakeTxTransferERC20(ctx, from, to, token, amount, nonceOffset)
	if err != nil {
		return nil, fmt.Errorf("failed to make ERC20 transfer tx: %w", err)
	}

	return tx, nil
}
