package mayachain

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

// ProviderEvm handles MayaChain swaps for EVM chains (Arbitrum)
// MayaChain supports ETH and ARB chains, using the same router contract interface as THORChain
type ProviderEvm struct {
	client *Client
	rpc    *ethclient.Client
	sdk    *evm.SDK
}

// NewProviderEvm creates a new MayaChain EVM provider
func NewProviderEvm(client *Client, rpc *ethclient.Client, sdk *evm.SDK) *ProviderEvm {
	return &ProviderEvm{
		client: client,
		rpc:    rpc,
		sdk:    sdk,
	}
}

func (p *ProviderEvm) validateEvm(from evm_swap.From, to evm_swap.To) error {
	_, err := parseMayaNetwork(from.Chain)
	if err != nil {
		return fmt.Errorf("unsupported 'from' chain for MayaChain: %w", err)
	}

	_, err = parseMayaNetwork(to.Chain)
	if err != nil {
		return fmt.Errorf("unsupported 'to' chain for MayaChain: %w", err)
	}

	return nil
}

func (p *ProviderEvm) getTokenDecimals(ctx context.Context, tokenAddress common.Address) (uint8, error) {
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

// convertDecimals converts amount from originalDecimals to desiredDecimals and returns both
// the converted amount and the exact amount that should be used in the transaction
// to match what was quoted for
func convertDecimals(amount *big.Int, originalDecimals, desiredDecimals uint8) (*big.Int, *big.Int) {
	if originalDecimals == desiredDecimals {
		return new(big.Int).Set(amount), new(big.Int).Set(amount)
	}

	var convertedAmount *big.Int
	var exactAmount *big.Int

	if originalDecimals > desiredDecimals {
		divisor := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(originalDecimals-desiredDecimals)), nil)
		convertedAmount = new(big.Int).Div(amount, divisor)
		exactAmount = new(big.Int).Mul(convertedAmount, divisor)
	} else {
		multiplier := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(desiredDecimals-originalDecimals)), nil)
		convertedAmount = new(big.Int).Mul(amount, multiplier)
		exactAmount = new(big.Int).Set(amount)
	}

	return convertedAmount, exactAmount
}

// MakeTx creates a swap transaction via MayaChain
// This supports swaps from Arbitrum to other MayaChain-supported chains
func (p *ProviderEvm) MakeTx(
	ctx context.Context,
	from evm_swap.From,
	to evm_swap.To,
) (*big.Int, []byte, error) {
	if err := p.validateEvm(from, to); err != nil {
		return nil, nil, fmt.Errorf("invalid swap: %w", err)
	}

	fromMayaNet, err := parseMayaNetwork(from.Chain)
	if err != nil {
		return nil, nil, fmt.Errorf("unsupported from chain: %w", err)
	}

	var fromAsset string
	if bytes.Equal(from.AssetID.Bytes(), evm.ZeroAddress.Bytes()) {
		nativeSymbol, er := from.Chain.NativeSymbol()
		if er != nil {
			return nil, nil, fmt.Errorf("failed to get native symbol: %w", er)
		}
		fromAsset = string(fromMayaNet) + "." + nativeSymbol
	} else {
		fromAsset, err = makeMayaAsset(ctx, p.client, from.Chain, from.AssetID.Hex())
		if err != nil {
			return nil, nil, fmt.Errorf("failed to resolve from asset: %w", err)
		}
	}

	tokenDecimals, err := p.getTokenDecimals(ctx, from.AssetID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get token decimals: %w", err)
	}

	// MayaChain uses 10 decimals for CACAO (native) and 8 decimals for most assets
	mayaAmount, exactAmount := convertDecimals(from.Amount, tokenDecimals, 8)

	toAsset, err := makeMayaAsset(ctx, p.client, to.Chain, to.AssetID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve to asset: %w", err)
	}

	quote, err := p.client.getQuote(ctx, quoteSwapRequest{
		FromAsset:         fromAsset,
		ToAsset:           toAsset,
		Amount:            mayaAmount.String(),
		Destination:       to.Address,
		StreamingInterval: defaultStreamingInterval,
		StreamingQuantity: defaultStreamingQuantity,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get quote: %w", err)
	}

	dustThreshold, err := strconv.ParseUint(quote.DustThreshold, 10, 64)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse dust threshold: %w", err)
	}

	if mayaAmount.Uint64() < dustThreshold {
		return nil, nil, fmt.Errorf(
			"amount %s (8-decimal: %s, exact: %s) below dust threshold %d",
			from.Amount.String(),
			mayaAmount.String(),
			exactAmount.String(),
			dustThreshold,
		)
	}

	// MayaChain uses the same router contract interface as THORChain
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
		// Native token swap (ETH on Arbitrum)
		data = router.PackDepositWithExpiry(
			vaultAddr,
			evm.ZeroAddress,
			big.NewInt(0),
			quote.Memo,
			expiry,
		)
		value = exactAmount
	} else {
		// ERC20 token swap
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
		0, // nonceOffset
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build tx: %w", err)
	}

	expectedOut, ok := new(big.Int).SetString(quote.ExpectedAmountOut, 10)
	if !ok {
		return nil, nil, fmt.Errorf("failed to parse expected amount out: %s", quote.ExpectedAmountOut)
	}

	targetTokenAddr := common.HexToAddress(to.AssetID)
	targetDecimals, err := p.getTokenDecimals(ctx, targetTokenAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get target token decimals: %w", err)
	}

	realExpectedOut, _ := convertDecimals(expectedOut, 8, targetDecimals)

	return realExpectedOut, unsignedTx, nil
}



