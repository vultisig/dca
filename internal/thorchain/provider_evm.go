package thorchain

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	evm_swap "github.com/vultisig/dca/internal/evm"
	"github.com/vultisig/recipes/sdk/evm"
	"github.com/vultisig/recipes/sdk/evm/codegen/erc20"
	"github.com/vultisig/recipes/sdk/evm/codegen/thorchain_router"
)

type EvmProvider struct {
	client *Client
	rpc    *ethclient.Client
	sdk    *evm.SDK
}

func NewProviderEvm(client *Client, rpc *ethclient.Client, sdk *evm.SDK) *EvmProvider {
	return &EvmProvider{
		client: client,
		rpc:    rpc,
		sdk:    sdk,
	}
}

func (p *EvmProvider) validateEvm(from evm_swap.From, to evm_swap.To) error {
	_, err := parseThorNetwork(from.Chain)
	if err != nil {
		return fmt.Errorf("unsupported 'from' chain: %w", err)
	}

	_, err = parseThorNetwork(to.Chain)
	if err != nil {
		return fmt.Errorf("unsupported 'to' chain: %w", err)
	}

	return nil
}

func (p *EvmProvider) getTokenDecimals(ctx context.Context, tokenAddress common.Address) (uint8, error) {
	if bytes.Equal(tokenAddress.Bytes(), evm.ZeroAddress.Bytes()) {
		return 18, nil
	}

	erc20Contract := erc20.NewErc20()
	decimals, err := evm.CallReadonly(
		ctx,
		p.rpc,
		erc20Contract,
		tokenAddress,
		erc20Contract.PackDecimals(),
		erc20Contract.UnpackDecimals,
		nil,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to get token decimals: %w", err)
	}

	return decimals, nil
}

// convertToThorDecimals converts amount to THORChain's 8 decimals and returns both
// the normalized amount and the exact amount that should be used in the transaction
// to match what was quoted for
func convertToThorDecimals(amount *big.Int, originalDecimals uint8) (*big.Int, *big.Int) {
	const thorChainDecimals = 8

	if originalDecimals == thorChainDecimals {
		return new(big.Int).Set(amount), new(big.Int).Set(amount)
	}

	var thorAmount *big.Int
	var exactAmount *big.Int

	if originalDecimals > thorChainDecimals {
		divisor := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(originalDecimals-thorChainDecimals)), nil)
		thorAmount = new(big.Int).Div(amount, divisor)
		exactAmount = new(big.Int).Mul(thorAmount, divisor)
	} else {
		multiplier := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(thorChainDecimals-originalDecimals)), nil)
		thorAmount = new(big.Int).Mul(amount, multiplier)
		exactAmount = new(big.Int).Set(amount)
	}

	return thorAmount, exactAmount
}

func (p *EvmProvider) MakeTx(
	ctx context.Context,
	from evm_swap.From,
	to evm_swap.To,
) (*big.Int, []byte, error) {
	if err := p.validateEvm(from, to); err != nil {
		return nil, nil, fmt.Errorf("invalid swap: %w", err)
	}

	fromThorNet, err := parseThorNetwork(from.Chain)
	if err != nil {
		return nil, nil, fmt.Errorf("unsupported from chain: %w", err)
	}

	var fromAsset string
	if bytes.Equal(from.AssetID.Bytes(), evm.ZeroAddress.Bytes()) {
		nativeSymbol, er := from.Chain.NativeSymbol()
		if er != nil {
			return nil, nil, fmt.Errorf("failed to get native symbol: %w", er)
		}
		fromAsset = string(fromThorNet) + "." + nativeSymbol
	} else {
		fromAsset, err = makeThorAsset(ctx, p.client, from.Chain, from.AssetID.Hex())
		if err != nil {
			return nil, nil, fmt.Errorf("failed to resolve from asset: %w", err)
		}
	}

	tokenDecimals, err := p.getTokenDecimals(ctx, from.AssetID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get token decimals: %w", err)
	}

	thorAmount, exactAmount := convertToThorDecimals(from.Amount, tokenDecimals)

	toAsset, err := makeThorAsset(ctx, p.client, to.Chain, to.AssetID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve to asset: %w", err)
	}

	quote, err := p.client.getQuote(ctx, quoteSwapRequest{
		FromAsset:         fromAsset,
		ToAsset:           toAsset,
		Amount:            thorAmount.String(),
		Destination:       to.Address,
		StreamingInterval: defaultStreamingInterval,
		StreamingQuantity: defaultStreamingQuantity,
		ToleranceBps:      defaultToleranceBps,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get quote: %w", err)
	}

	dustThreshold, err := strconv.ParseUint(quote.DustThreshold, 10, 64)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse dust threshold: %w", err)
	}

	if thorAmount.Uint64() < dustThreshold {
		return nil, nil, fmt.Errorf(
			"amount %s (8-decimal: %s, exact: %s) below dust threshold %d",
			from.Amount.String(),
			thorAmount.String(),
			exactAmount.String(),
			dustThreshold,
		)
	}

	router := thorchain_router.NewThorchainRouter()
	routerAddr := common.HexToAddress(quote.Router)
	vaultAddr := common.HexToAddress(quote.InboundAddress)

	var expiry *big.Int
	if quote.Expiry > 0 {
		expiry = big.NewInt(quote.Expiry)
	} else {
		expiry = big.NewInt(time.Now().Unix() + 3600)
	}

	var data []byte
	var value *big.Int
	if bytes.Equal(from.AssetID.Bytes(), evm.ZeroAddress.Bytes()) {
		data = router.PackDepositWithExpiry(
			vaultAddr,
			evm.ZeroAddress,
			big.NewInt(0),
			quote.Memo,
			expiry,
		)
		value = exactAmount
	} else {
		data = router.PackDepositWithExpiry(
			vaultAddr,
			from.AssetID,
			exactAmount,
			quote.Memo,
			expiry,
		)
		value = big.NewInt(0)
	}

	unsignedTx, err := p.sdk.MakeTx(
		ctx,
		from.Address,
		routerAddr,
		value,
		data,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build tx: %w", err)
	}

	expectedOut, ok := new(big.Int).SetString(quote.ExpectedAmountOut, 10)
	if !ok {
		return nil, nil, fmt.Errorf("failed to parse expected amount out: %w", err)
	}

	return expectedOut, unsignedTx, nil
}
