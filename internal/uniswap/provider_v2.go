package uniswap

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	evm_swap "github.com/vultisig/dca/internal/evm"
	"github.com/vultisig/recipes/sdk/evm"
	"github.com/vultisig/recipes/sdk/evm/codegen/uniswapv2_router"
	rcommon "github.com/vultisig/vultisig-go/common"
)

type ProviderV2 struct {
	chain  rcommon.Chain
	rpc    *ethclient.Client
	sdk    *evm.SDK
	router common.Address
}

func NewProviderV2(chain rcommon.Chain, rpc *ethclient.Client, evmSDK *evm.SDK, router common.Address) *ProviderV2 {
	return &ProviderV2{
		chain:  chain,
		rpc:    rpc,
		sdk:    evmSDK,
		router: router,
	}
}

func (p *ProviderV2) validatePath(from evm_swap.From, to evm_swap.To) error {
	if from.Chain != p.chain {
		return fmt.Errorf("unsupported from.Chain: %s", from.Chain)
	}
	if to.Chain != p.chain {
		return fmt.Errorf("unsupported to.Chain: %s", to.Chain)
	}
	return nil
}

func (p *ProviderV2) MakeTx(
	ctx context.Context,
	from evm_swap.From,
	to evm_swap.To,
) (*big.Int, []byte, error) {
	if err := p.validatePath(from, to); err != nil {
		return nil, nil, fmt.Errorf("invalid path: %w", err)
	}

	router := uniswapv2_router.NewUniswapv2Router()

	path := []common.Address{from.AssetID, common.HexToAddress(to.AssetID)}
	deadline := big.NewInt(time.Now().Unix() + 60)

	amountsOut, err := evm.CallReadonly(
		ctx,
		p.rpc,
		router,
		p.router,
		router.PackGetAmountsOut(from.Amount, path),
		router.UnpackGetAmountsOut,
		nil,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute amount out: %w", err)
	}
	if len(amountsOut) == 0 {
		return nil, nil, fmt.Errorf("unexpected empty amountsOut")
	}

	lastAmountOut := amountsOut[len(amountsOut)-1]
	amountOutMin := deductSlippage(lastAmountOut, slippageBips)

	var data []byte
	var value *big.Int

	toAddress := common.HexToAddress(to.Address)
	if bytes.Equal(from.AssetID.Bytes(), evm.ZeroAddress.Bytes()) {
		data = router.PackSwapExactETHForTokens(amountOutMin, path, toAddress, deadline)
		value = from.Amount
	} else if bytes.Equal(common.HexToAddress(to.AssetID).Bytes(), evm.ZeroAddress.Bytes()) {
		data = router.PackSwapExactTokensForETH(from.Amount, amountOutMin, path, toAddress, deadline)
		value = big.NewInt(0)
	} else {
		data = router.PackSwapExactTokensForTokens(from.Amount, amountOutMin, path, toAddress, deadline)
		value = big.NewInt(0)
	}

	unsignedTx, err := p.sdk.MakeTx(
		ctx,
		from.Address,
		p.router,
		value,
		data,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build tx: %w", err)
	}

	return lastAmountOut, unsignedTx, nil
}

func deductSlippage(amount *big.Int, slippageBips uint64) *big.Int {
	if amount == nil || amount.Sign() <= 0 {
		return big.NewInt(0)
	}

	bipsTotal := big.NewInt(10000)
	slippageBig := new(big.Int).SetUint64(slippageBips)

	// Calculate: amount * (10000 - slippageBips) / 10000
	multiplier := new(big.Int).Sub(bipsTotal, slippageBig)
	result := new(big.Int).Mul(amount, multiplier)
	result.Div(result, bipsTotal)

	return result
}
