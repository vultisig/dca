package evm

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/recipes/sdk/evm"
	"github.com/vultisig/recipes/sdk/swap"
	rcommon "github.com/vultisig/vultisig-go/common"
)

// wellKnownTokens maps token addresses to their symbols for THORChain compatibility.
// Addresses are stored lowercase for case-insensitive lookup.
var wellKnownTokens = map[string]string{
	// USDC
	"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC",
	// USDT
	"0xdac17f958d2ee523a2206206994597c13d831ec7": "USDT",
	// WETH
	"0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "WETH",
	// DAI
	"0x6b175474e89094c44da98b954eedeac495271d0f": "DAI",
	// WBTC
	"0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": "WBTC",
	// LINK
	"0x514910771af9ca656af840dff83e8264ecf986ca": "LINK",
	// UNI
	"0x1f9840a85d5af5bf1d1762f925bdaddc4201f984": "UNI",
}

// getTokenSymbol returns the symbol for a token address.
// Falls back to a generic symbol if not in the registry.
func getTokenSymbol(address string) string {
	if address == "" {
		return ""
	}
	lower := strings.ToLower(address)
	if sym, ok := wellKnownTokens[lower]; ok {
		return sym
	}
	return "TOKEN"
}

type CanonicalProvider struct {
	adapter *swap.ChainAdapter
	sdk     *evm.SDK
	chain   rcommon.Chain
}

func NewCanonicalProvider(chain rcommon.Chain, sdk *evm.SDK) *CanonicalProvider {
	return &CanonicalProvider{
		adapter: swap.NewChainAdapter(chain.String()),
		sdk:     sdk,
		chain:   chain,
	}
}

func (p *CanonicalProvider) buildSwapInput(from From, to To) swap.SwapInput {
	fromToken := from.AssetID.Hex()
	fromSymbol, _ := p.chain.NativeSymbol()
	if from.AssetID == evm.ZeroAddress {
		fromToken = ""
	} else {
		if from.Symbol != "" {
			fromSymbol = from.Symbol
		} else {
			fromSymbol = getTokenSymbol(fromToken)
		}
	}

	toToken := to.AssetID
	toSymbol, _ := to.Chain.NativeSymbol()
	if toToken == evm.ZeroAddress.Hex() || toToken == "" {
		toToken = ""
	} else {
		if to.Symbol != "" {
			toSymbol = to.Symbol
		} else {
			toSymbol = getTokenSymbol(toToken)
		}
	}

	toChainStr := to.Chain.String()
	if to.Chain == from.Chain {
		toChainStr = ""
	}

	return swap.SwapInput{
		FromToken:   fromToken,
		FromSymbol:  fromSymbol,
		FromAmount:  from.Amount,
		FromAddress: from.Address.Hex(),

		ToChain:   toChainStr,
		ToToken:   toToken,
		ToSymbol:  toSymbol,
		ToAddress: to.Address,
	}
}

func (p *CanonicalProvider) GetApprovalSpender(
	ctx context.Context,
	from From,
	to To,
) (ecommon.Address, error) {
	input := p.buildSwapInput(from, to)

	result, err := p.adapter.GetSwap(ctx, input)
	if err != nil {
		return ecommon.Address{}, fmt.Errorf("failed to get swap for approval check: %w", err)
	}

	if result.RouterAddress == "" {
		return ecommon.Address{}, fmt.Errorf("no router address available")
	}

	return ecommon.HexToAddress(result.RouterAddress), nil
}

func (p *CanonicalProvider) MakeTx(
	ctx context.Context,
	from From,
	to To,
) (*big.Int, []byte, error) {
	log := logrus.WithFields(logrus.Fields{
		"provider":   "canonical",
		"fromChain":  from.Chain.String(),
		"fromAsset":  from.AssetID.String(),
		"fromAmount": from.Amount.String(),
		"toChain":    to.Chain.String(),
		"toAsset":    to.AssetID,
		"toAddress":  to.Address,
	})

	input := p.buildSwapInput(from, to)

	log.Debug("building canonical swap transaction")

	result, err := p.adapter.GetSwap(ctx, input)
	if err != nil {
		log.WithError(err).Debug("canonical swap failed")
		return nil, nil, fmt.Errorf("canonical swap failed: %w", err)
	}

	routerAddr := ecommon.HexToAddress(result.RouterAddress)

	unsignedTx, err := p.sdk.MakeTx(
		ctx,
		from.Address,
		routerAddr,
		result.TxValue,
		result.TxData,
		0,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build unsigned tx: %w", err)
	}

	log.WithFields(logrus.Fields{
		"provider":    result.Provider,
		"expectedOut": result.ExpectedAmountOut.String(),
		"router":      result.RouterAddress,
	}).Info("canonical swap transaction built")

	return result.ExpectedAmountOut, unsignedTx, nil
}
