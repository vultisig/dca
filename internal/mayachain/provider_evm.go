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
	evm_swap "github.com/vultisig/app-recurring/internal/evm"
	"github.com/vultisig/recipes/sdk/evm"
	"github.com/vultisig/recipes/sdk/evm/codegen/erc20"
	"github.com/vultisig/recipes/sdk/evm/codegen/thorchain_router"
	vcommon "github.com/vultisig/vultisig-go/common"
)

type ProviderEvm struct {
	client   *Client
	rpc      *ethclient.Client
	sdk      *evm.SDK
	chainRpc map[string]*ethclient.Client
}

func NewProviderEvm(client *Client, rpc *ethclient.Client, sdk *evm.SDK, chainRpc map[string]*ethclient.Client) *ProviderEvm {
	return &ProviderEvm{
		client:   client,
		rpc:      rpc,
		sdk:      sdk,
		chainRpc: chainRpc,
	}
}

func (p *ProviderEvm) Name() string {
	return "mayachain"
}

func (p *ProviderEvm) validateEvm(from evm_swap.From, to evm_swap.To) error {
	_, err := parseMayaNetwork(from.Chain)
	if err != nil {
		return fmt.Errorf("unsupported 'from' chain: %w", err)
	}

	_, err = parseMayaNetwork(to.Chain)
	if err != nil {
		return fmt.Errorf("unsupported 'to' chain: %w", err)
	}

	return nil
}

func (p *ProviderEvm) getTokenDecimals(ctx context.Context, tokenAddress common.Address) (uint8, error) {
	return p.getTokenDecimalsWithRpc(ctx, p.rpc, tokenAddress)
}

func (p *ProviderEvm) getTokenDecimalsWithRpc(ctx context.Context, rpc *ethclient.Client, tokenAddress common.Address) (uint8, error) {
	if bytes.Equal(tokenAddress.Bytes(), evm.ZeroAddress.Bytes()) {
		return 18, nil
	}

	erc20Contract := erc20.NewErc20()
	decimals, err := evm.CallReadonly(
		ctx,
		rpc,
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

func (p *ProviderEvm) getTargetChainRpc(chain string) (*ethclient.Client, error) {
	rpc, ok := p.chainRpc[chain]
	if !ok {
		return nil, fmt.Errorf("no RPC configured for chain: %s", chain)
	}
	return rpc, nil
}

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
		fromAsset, err = p.makeMayaAsset(ctx, from.Chain, from.AssetID.Hex())
		if err != nil {
			return nil, nil, fmt.Errorf("failed to resolve from asset: %w", err)
		}
	}

	tokenDecimals, err := p.getTokenDecimals(ctx, from.AssetID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get token decimals: %w", err)
	}

	mayaAmount, exactAmount := convertDecimals(from.Amount, tokenDecimals, 8)

	toAsset, err := MakeMayaAsset(ctx, p.client, to.Chain, to.AssetID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve to asset: %w", err)
	}

	quote, err := p.client.GetQuote(ctx, QuoteSwapRequest{
		FromAsset:         fromAsset,
		ToAsset:           toAsset,
		Amount:            mayaAmount.String(),
		Destination:       to.Address,
		StreamingInterval: DefaultStreamingInterval,
		StreamingQuantity: DefaultStreamingQuantity,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get quote: %w", err)
	}

	var dustThreshold uint64
	if quote.DustThreshold != "" {
		dustThreshold, err = strconv.ParseUint(quote.DustThreshold, 10, 64)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse dust threshold: %w", err)
		}
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
		0,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build tx: %w", err)
	}

	expectedOut, ok := new(big.Int).SetString(quote.ExpectedAmountOut, 10)
	if !ok {
		return nil, nil, fmt.Errorf("failed to parse expected amount out: %s", quote.ExpectedAmountOut)
	}

	targetTokenAddr := common.HexToAddress(to.AssetID)
	var targetDecimals uint8
	if bytes.Equal(targetTokenAddr.Bytes(), evm.ZeroAddress.Bytes()) {
		targetDecimals = 18
	} else {
		targetRpc, err := p.getTargetChainRpc(to.Chain.String())
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get target chain RPC: %w", err)
		}
		targetDecimals, err = p.getTokenDecimalsWithRpc(ctx, targetRpc, targetTokenAddr)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get target token decimals: %w", err)
		}
	}

	realExpectedOut, _ := convertDecimals(expectedOut, 8, targetDecimals)

	return realExpectedOut, unsignedTx, nil
}

func (p *ProviderEvm) makeMayaAsset(ctx context.Context, chain vcommon.Chain, assetHex string) (string, error) {
	pools, err := p.client.getPools(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get pools: %w", err)
	}

	mayaNet, err := parseMayaNetwork(chain)
	if err != nil {
		return "", fmt.Errorf("unsupported chain: %w", err)
	}

	networkPrefix := string(mayaNet) + "."

	for _, pp := range pools {
		if len(pp.Asset) <= len(networkPrefix) {
			continue
		}
		if pp.Asset[:len(networkPrefix)] != networkPrefix {
			continue
		}

		tokenPart := pp.Asset[len(networkPrefix):]
		dashIdx := -1
		for i, ch := range tokenPart {
			if ch == '-' {
				dashIdx = i
				break
			}
		}

		if dashIdx == -1 {
			continue
		}

		poolAddress := tokenPart[dashIdx+1:]
		if len(poolAddress) > 2 && poolAddress[:2] == "0x" {
			poolAddress = poolAddress[2:]
		}
		if len(assetHex) > 2 && assetHex[:2] == "0x" {
			assetHex = assetHex[2:]
		}

		if len(poolAddress) != len(assetHex) {
			continue
		}

		match := true
		for i := 0; i < len(poolAddress); i++ {
			c1 := poolAddress[i]
			c2 := assetHex[i]
			if c1 >= 'A' && c1 <= 'Z' {
				c1 = c1 + 32
			}
			if c2 >= 'A' && c2 <= 'Z' {
				c2 = c2 + 32
			}
			if c1 != c2 {
				match = false
				break
			}
		}

		if match {
			return pp.Asset, nil
		}
	}

	return "", fmt.Errorf("asset not found in MayaChain pools for chain %s and asset %s", mayaNet, assetHex)
}
