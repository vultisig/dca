package evm

import (
	"context"
	"fmt"
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/vultisig/recipes/sdk/evm"
	"github.com/vultisig/recipes/sdk/evm/codegen/erc20"
)

type approveService struct {
	rpc *ethclient.Client
	sdk *evm.SDK
}

func newApproveService(rpc *ethclient.Client, sdk *evm.SDK) *approveService {
	return &approveService{
		rpc: rpc,
		sdk: sdk,
	}
}

func (a *approveService) CheckAllowance(
	ctx context.Context,
	tokenAddress, owner, spender common.Address,
	amount *big.Int,
) (bool, []byte, error) {
	var zero common.Address
	if tokenAddress == zero {
		return false, nil, nil
	}

	erc20Contract := erc20.NewErc20()

	allowanceData := erc20Contract.PackAllowance(owner, spender)
	currentAllowance, err := evm.CallReadonly(
		ctx,
		a.rpc,
		erc20Contract,
		tokenAddress,
		allowanceData,
		erc20Contract.UnpackAllowance,
		nil,
	)
	if err != nil {
		return false, nil, fmt.Errorf("failed to check allowance: %w", err)
	}

	if currentAllowance.Cmp(amount) >= 0 {
		return false, nil, nil
	}

	unsignedTx, err := a.sdk.MakeTx(
		ctx,
		owner,
		tokenAddress,
		big.NewInt(0),
		erc20Contract.PackApprove(spender, big.NewInt(math.MaxInt64)),
	)
	if err != nil {
		return false, nil, fmt.Errorf("failed to make approve tx: %w", err)
	}

	return true, unsignedTx, nil
}
