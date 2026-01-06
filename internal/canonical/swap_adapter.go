// Package canonical provides adapters for using the canonical swap router
// from the recipes repository.
//
// This package bridges the app-recurring Provider interface with the
// canonical swap router, providing a unified swap experience across all
// supported chains and providers.
//
// Usage:
//
//	// Create adapter for a specific chain
//	adapter, err := canonical.NewSwapAdapter("Ethereum")
//	if err != nil {
//	    // handle unsupported chain
//	}
//
//	// Use it like any other provider
//	amountOut, txData, err := adapter.MakeTx(ctx, from, to)
//
// The canonical router automatically selects the best available provider
// in priority order: THORChain > Mayachain > LiFi > 1inch > Jupiter > Uniswap
package canonical

import (
	"context"
	"fmt"
	"math/big"

	"github.com/sirupsen/logrus"
	"github.com/vultisig/recipes/sdk/swap"
)

// SwapAdapter wraps the canonical swap router for use in app-recurring.
// It implements a similar interface to the existing Provider types.
type SwapAdapter struct {
	chainAdapter *swap.ChainAdapter
	chain        string
}

// NewSwapAdapter creates a new swap adapter for a specific chain.
// Returns an error if the chain is not supported by the canonical router.
func NewSwapAdapter(chain string) (*SwapAdapter, error) {
	if !IsChainSupported(chain) {
		return nil, fmt.Errorf("unsupported chain: %s", chain)
	}
	return &SwapAdapter{
		chainAdapter: swap.NewChainAdapter(chain),
		chain:        chain,
	}, nil
}

// From represents the source of a swap (matches evm.From pattern).
type From struct {
	Token    string   // Contract address (empty for native)
	Symbol   string   // Token symbol
	Decimals int      // Token decimals
	Amount   *big.Int // Amount in base units
	Address  string   // Sender address
}

// To represents the destination of a swap (matches evm.To pattern).
type To struct {
	Chain    string // Destination chain (empty = same chain)
	Token    string // Contract address (empty for native)
	Symbol   string // Token symbol
	Decimals int    // Token decimals
	Address  string // Recipient address
}

// MakeTx creates a swap transaction using the canonical router.
// This method matches the Provider interface signature in app-recurring.
func (a *SwapAdapter) MakeTx(ctx context.Context, from From, to To) (*big.Int, []byte, error) {
	toChain := to.Chain
	if toChain == "" {
		toChain = a.chain
	}

	log := logrus.WithFields(logrus.Fields{
		"from_chain":  a.chain,
		"from_symbol": from.Symbol,
		"to_chain":    toChain,
		"to_symbol":   to.Symbol,
		"amount":      from.Amount.String(),
	})
	log.Debug("Building swap transaction")

	input := swap.SwapInput{
		FromToken:    from.Token,
		FromSymbol:   from.Symbol,
		FromDecimals: from.Decimals,
		FromAmount:   from.Amount,
		FromAddress:  from.Address,

		ToChain:    to.Chain,
		ToToken:    to.Token,
		ToSymbol:   to.Symbol,
		ToDecimals: to.Decimals,
		ToAddress:  to.Address,
	}

	amountOut, txData, err := a.chainAdapter.MakeTx(ctx, input)
	if err != nil {
		log.WithError(err).Warn("Failed to build swap transaction")
		return nil, nil, fmt.Errorf("chain %s: failed to build swap transaction: %w", a.chain, err)
	}

	log.WithField("amount_out", amountOut.String()).Info("Swap transaction built successfully")
	return amountOut, txData, nil
}

// GetQuote gets a quote without building the transaction.
func (a *SwapAdapter) GetQuote(ctx context.Context, from From, to To) (*swap.Quote, error) {
	toChain := to.Chain
	if toChain == "" {
		toChain = a.chain
	}

	log := logrus.WithFields(logrus.Fields{
		"from_chain":  a.chain,
		"from_symbol": from.Symbol,
		"to_chain":    toChain,
		"to_symbol":   to.Symbol,
		"amount":      from.Amount.String(),
	})
	log.Debug("Fetching swap quote")

	fromAsset := swap.Asset{
		Chain:    a.chain,
		Symbol:   from.Symbol,
		Address:  from.Token,
		Decimals: from.Decimals,
	}

	toAsset := swap.Asset{
		Chain:    toChain,
		Symbol:   to.Symbol,
		Address:  to.Token,
		Decimals: to.Decimals,
	}

	quote, err := swap.GetQuote(ctx, swap.QuoteRequest{
		From:        fromAsset,
		To:          toAsset,
		Amount:      from.Amount,
		Sender:      from.Address,
		Destination: to.Address,
	})
	if err != nil {
		log.WithError(err).Warn("Failed to get swap quote")
		return nil, fmt.Errorf("chain %s: failed to get quote: %w", a.chain, err)
	}

	log.WithFields(logrus.Fields{
		"provider":   quote.Provider,
		"amount_out": quote.ExpectedOutput.String(),
	}).Info("Swap quote fetched successfully")
	return quote, nil
}

// IsChainSupported checks if the canonical router supports a chain.
func IsChainSupported(chain string) bool {
	chains := swap.GetSupportedChains()
	for _, c := range chains {
		if c == chain {
			return true
		}
	}
	return false
}

// GetSupportedChains returns all chains supported by the canonical router.
func GetSupportedChains() []string {
	return swap.GetSupportedChains()
}

// CanSwap checks if a swap is possible between two assets.
func CanSwap(ctx context.Context, fromChain, fromToken, toChain, toToken string) bool {
	from := swap.Asset{Chain: fromChain, Address: fromToken}
	to := swap.Asset{Chain: toChain, Address: toToken}
	return swap.CanSwap(ctx, from, to)
}

// GetProviderStatus returns the status of a specific provider for a chain.
func GetProviderStatus(ctx context.Context, provider, chain string) (*swap.ProviderStatus, error) {
	return swap.GetProviderStatus(ctx, provider, chain)
}

// ValidateCrossChainRoute validates that a cross-chain swap route is available.
// This replaces the direct thorchain.IsThorChainSupported checks.
func ValidateCrossChainRoute(ctx context.Context, fromChain, toChain string) error {
	log := logrus.WithFields(logrus.Fields{
		"from_chain": fromChain,
		"to_chain":   toChain,
	})
	log.Debug("Validating cross-chain route")

	from := swap.Asset{Chain: fromChain}
	to := swap.Asset{Chain: toChain}

	route, err := swap.FindRoute(ctx, from, to)
	if err != nil {
		log.WithError(err).Warn("Failed to find cross-chain route")
		return fmt.Errorf("no route available from %s to %s: %w", fromChain, toChain, err)
	}

	if !route.IsSupported {
		log.Warn("Cross-chain route not supported")
		return fmt.Errorf("route from %s to %s not supported", fromChain, toChain)
	}

	log.WithField("provider", route.Provider).Info("Cross-chain route validated successfully")
	return nil
}

