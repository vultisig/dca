package oneinch

import (
	"bytes"
	"context"
	"fmt"
	"math/big"

	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/ethclient"
	evm_swap "github.com/vultisig/dca/internal/evm"
	"github.com/vultisig/recipes/sdk/evm"
)

type Provider struct {
	client *Client
	rpc    *ethclient.Client
	sdk    *evm.SDK
}

func NewProvider(client *Client, rpc *ethclient.Client, sdk *evm.SDK) *Provider {
	return &Provider{
		client: client,
		rpc:    rpc,
		sdk:    sdk,
	}
}

func (p *Provider) validateSwap(from evm_swap.From, to evm_swap.To) error {
	if !from.Chain.IsEvm() {
		return fmt.Errorf("from chain %s is not EVM", from.Chain.String())
	}

	if !to.Chain.IsEvm() {
		return fmt.Errorf("to chain %s is not EVM", to.Chain.String())
	}

	if from.Chain != to.Chain {
		return fmt.Errorf("1inch only supports same-chain swaps: from=%s, to=%s", from.Chain.String(), to.Chain.String())
	}

	return nil
}

func (p *Provider) MakeTx(
	ctx context.Context,
	from evm_swap.From,
	to evm_swap.To,
) (*big.Int, []byte, error) {
	err := p.validateSwap(from, to)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid swap: %w", err)
	}

	srcToken := from.AssetID.Hex()
	if bytes.Equal(from.AssetID.Bytes(), evm.ZeroAddress.Bytes()) {
		srcToken = NativeTokenAddress
	}

	dstToken := to.AssetID
	if to.AssetID == "" {
		dstToken = NativeTokenAddress
	}

	swapResp, err := p.client.GetSwap(ctx, swapRequest{
		Chain:        from.Chain,
		Src:          srcToken,
		Dst:          dstToken,
		Amount:       from.Amount.String(),
		From:         from.Address.Hex(),
		Receiver:     to.Address,
		SlippagePerc: DefaultSlippagePercent,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get swap from 1inch: %w", err)
	}

	toAmount, ok := new(big.Int).SetString(swapResp.DstAmount, 10)
	if !ok {
		return nil, nil, fmt.Errorf("failed to parse toAmount: %s", swapResp.DstAmount)
	}

	txValue, ok := new(big.Int).SetString(swapResp.Tx.Value, 10)
	if !ok {
		return nil, nil, fmt.Errorf("failed to parse tx value: %s", swapResp.Tx.Value)
	}

	txData, err := hexutil.Decode(swapResp.Tx.Data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode tx data: %w", err)
	}

	routerAddr := ecommon.HexToAddress(swapResp.Tx.To)

	unsignedTx, err := p.sdk.MakeTx(
		ctx,
		from.Address,
		routerAddr,
		txValue,
		txData,
		0, // nonceOffset: swaps don't need offset
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build unsigned tx: %w", err)
	}

	return toAmount, unsignedTx, nil
}
