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
//	adapter := canonical.NewSwapAdapter("Ethereum")
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

	"github.com/vultisig/recipes/sdk/swap"
)

// SwapAdapter wraps the canonical swap router for use in app-recurring.
// It implements a similar interface to the existing Provider types.
type SwapAdapter struct {
	chainAdapter *swap.ChainAdapter
	chain        string
}

// NewSwapAdapter creates a new swap adapter for a specific chain.
func NewSwapAdapter(chain string) *SwapAdapter {
	return &SwapAdapter{
		chainAdapter: swap.NewChainAdapter(chain),
		chain:        chain,
	}
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

	return a.chainAdapter.MakeTx(ctx, input)
}

// GetQuote gets a quote without building the transaction.
func (a *SwapAdapter) GetQuote(ctx context.Context, from From, to To) (*swap.Quote, error) {
	fromAsset := swap.Asset{
		Chain:    a.chain,
		Symbol:   from.Symbol,
		Address:  from.Token,
		Decimals: from.Decimals,
	}

	toChain := to.Chain
	if toChain == "" {
		toChain = a.chain
	}

	toAsset := swap.Asset{
		Chain:    toChain,
		Symbol:   to.Symbol,
		Address:  to.Token,
		Decimals: to.Decimals,
	}

	return swap.GetQuote(ctx, swap.QuoteRequest{
		From:        fromAsset,
		To:          toAsset,
		Amount:      from.Amount,
		Sender:      from.Address,
		Destination: to.Address,
	})
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
	from := swap.Asset{Chain: fromChain}
	to := swap.Asset{Chain: toChain}

	route, err := swap.FindRoute(ctx, from, to)
	if err != nil {
		return fmt.Errorf("no route available from %s to %s: %w", fromChain, toChain, err)
	}

	if !route.IsSupported {
		return fmt.Errorf("route from %s to %s not supported", fromChain, toChain)
	}

	return nil
}

