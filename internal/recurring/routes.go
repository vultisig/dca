package recurring

import (
	"context"
	"fmt"

	"github.com/vultisig/app-recurring/internal/mayachain"
	"github.com/vultisig/app-recurring/internal/thorchain"
	"github.com/vultisig/vultisig-go/common"
)

// ChainRouteCapability defines what cross-chain providers a source chain has configured
type ChainRouteCapability struct {
	ThorChainEnabled bool
	MayaChainEnabled bool
	SameChainOnly    bool
}

// chainRouteCapabilities maps each chain to its configured cross-chain providers.
// This must match the actual provider configuration in cmd/worker/main.go.
//
// Based on live API data:
// - MayaChain supports: ARB, BTC, DASH, ETH, KUJI, THOR, XRD, ZEC
// - THORChain supports: AVAX, BASE, BCH, BSC, BTC, DOGE, ETH, GAIA, LTC, TRON, XRP, THOR
var chainRouteCapabilities = map[common.Chain]ChainRouteCapability{
	// EVM chains with both THORChain and MayaChain support
	common.Ethereum: {ThorChainEnabled: true, MayaChainEnabled: true},

	// EVM chains with MayaChain only (ARB is on Maya but not Thor)
	common.Arbitrum: {ThorChainEnabled: false, MayaChainEnabled: true},

	// EVM chains with THORChain only
	common.Avalanche: {ThorChainEnabled: true, MayaChainEnabled: false},
	common.BscChain:  {ThorChainEnabled: true, MayaChainEnabled: false},
	common.Base:      {ThorChainEnabled: true, MayaChainEnabled: false},

	// EVM chains with no cross-chain support (1inch same-chain only)
	common.Blast:       {SameChainOnly: true},
	common.Optimism:    {SameChainOnly: true},
	common.Polygon:     {SameChainOnly: true},
	common.Zksync:      {SameChainOnly: true},
	common.CronosChain: {SameChainOnly: true},

	// Bitcoin - has both THORChain and MayaChain providers
	common.Bitcoin: {ThorChainEnabled: true, MayaChainEnabled: true},

	// THORChain-only UTXO chains
	common.Litecoin:    {ThorChainEnabled: true, MayaChainEnabled: false},
	common.Dogecoin:    {ThorChainEnabled: true, MayaChainEnabled: false},
	common.BitcoinCash: {ThorChainEnabled: true, MayaChainEnabled: false},

	// THORChain-only other chains
	common.XRP:       {ThorChainEnabled: true, MayaChainEnabled: false},
	common.Tron:      {ThorChainEnabled: true, MayaChainEnabled: false},
	common.GaiaChain: {ThorChainEnabled: true, MayaChainEnabled: false},

	// MayaChain-only chains
	common.Dash:  {ThorChainEnabled: false, MayaChainEnabled: true},
	common.Zcash: {ThorChainEnabled: false, MayaChainEnabled: true},

	// THORChain (RUNE) - has both providers
	common.THORChain: {ThorChainEnabled: true, MayaChainEnabled: true},

	// Same-chain only (no cross-chain providers configured)
	common.Solana:    {SameChainOnly: true},
	common.MayaChain: {SameChainOnly: true}, // No swap providers configured for MayaChain as source
}

// ValidateAssetRoute validates that a cross-chain swap has an available destination pool.
// It checks only the provider(s) that will actually be used based on chain capabilities.
func ValidateAssetRoute(
	ctx context.Context,
	thorClient *thorchain.Client,
	mayaClient *mayachain.Client,
	fromChain, toChain common.Chain,
	toAsset string,
) error {
	if fromChain == toChain {
		return nil // Same-chain swaps don't need pool validation
	}

	cap, ok := chainRouteCapabilities[fromChain]
	if !ok || cap.SameChainOnly {
		return fmt.Errorf("no cross-chain providers for %s", fromChain)
	}

	var lastErr error

	// Try THORChain if enabled and supports the route
	if cap.ThorChainEnabled && thorClient != nil && thorchain.IsThorChainSupported(fromChain, toChain) {
		err := thorClient.ValidateAssetPool(ctx, toChain, toAsset)
		if err == nil {
			return nil // Found available pool on THORChain
		}
		lastErr = fmt.Errorf("THORChain: %w", err)
	}

	// Try MayaChain if enabled and supports the route
	if cap.MayaChainEnabled && mayaClient != nil && mayachain.IsMayaChainSupported(fromChain, toChain) {
		err := mayaClient.ValidateAssetPool(ctx, toChain, toAsset)
		if err == nil {
			return nil // Found available pool on MayaChain
		}
		lastErr = fmt.Errorf("MayaChain: %w", err)
	}

	if lastErr != nil {
		assetDesc := "native"
		if toAsset != "" {
			assetDesc = toAsset
		}
		return fmt.Errorf("route %s → %s (%s): destination asset not available: %w", fromChain, toChain, assetDesc, lastErr)
	}
	return fmt.Errorf("no provider supports %s → %s", fromChain, toChain)
}
