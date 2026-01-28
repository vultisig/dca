package recurring

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vultisig/app-recurring/internal/mayachain"
	"github.com/vultisig/app-recurring/internal/thorchain"
	"github.com/vultisig/vultisig-go/common"
)

func TestChainRouteCapabilities(t *testing.T) {
	// Verify all supported chains have a capability defined
	supportedChains := []common.Chain{
		common.Ethereum,
		common.Arbitrum,
		common.Avalanche,
		common.BscChain,
		common.Base,
		common.Blast,
		common.Optimism,
		common.Polygon,
		common.Bitcoin,
		common.Litecoin,
		common.Dogecoin,
		common.BitcoinCash,
		common.XRP,
		common.Tron,
		common.GaiaChain,
		common.Dash,
		common.Zcash,
		common.THORChain,
		common.Solana,
		common.MayaChain,
	}

	for _, chain := range supportedChains {
		t.Run(chain.String(), func(t *testing.T) {
			_, ok := chainRouteCapabilities[chain]
			assert.True(t, ok, "chain %s should have route capability defined", chain)
		})
	}
}

func TestValidateAssetRoute_SameChain(t *testing.T) {
	// Same chain swaps should skip validation
	ctx := context.Background()
	err := ValidateAssetRoute(ctx, nil, nil, common.Ethereum, common.Ethereum, "")
	assert.NoError(t, err, "same chain should skip validation")
}

func TestValidateAssetRoute_NoProviders(t *testing.T) {
	// Solana has no cross-chain providers
	ctx := context.Background()
	err := ValidateAssetRoute(ctx, nil, nil, common.Solana, common.Bitcoin, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no cross-chain providers")
}

func TestValidateAssetRoute_ThorChainAvailable(t *testing.T) {
	// Mock THORChain server with available pool
	thorServer := mockThorPoolsServer(t, []map[string]interface{}{
		{"asset": "BTC.BTC", "status": "Available"},
	})
	defer thorServer.Close()

	thorClient := thorchain.NewClient(thorServer.URL)

	ctx := context.Background()
	// ETH -> BTC should use THORChain
	err := ValidateAssetRoute(ctx, thorClient, nil, common.Ethereum, common.Bitcoin, "")
	assert.NoError(t, err, "should find available pool on THORChain")
}

func TestValidateAssetRoute_ThorChainStaged(t *testing.T) {
	// Mock THORChain server with staged pool
	thorServer := mockThorPoolsServer(t, []map[string]interface{}{
		{"asset": "BTC.BTC", "status": "Staged"},
	})
	defer thorServer.Close()

	// Mock MayaChain server with no BTC pool (BTC on Maya exists, but we mock empty for this test)
	mayaServer := mockMayaPoolsServer(t, []map[string]interface{}{})
	defer mayaServer.Close()

	thorClient := thorchain.NewClient(thorServer.URL)
	mayaClient := mayachain.NewClient(mayaServer.URL)

	ctx := context.Background()
	// ETH -> BTC where BTC is staged on THORChain and not found on MayaChain
	err := ValidateAssetRoute(ctx, thorClient, mayaClient, common.Ethereum, common.Bitcoin, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "destination asset not available")
}

func TestValidateAssetRoute_FallbackToMaya(t *testing.T) {
	// Mock THORChain server with no ARB pool (ARB not on Thor)
	thorServer := mockThorPoolsServer(t, []map[string]interface{}{
		{"asset": "ETH.ETH", "status": "Available"},
	})
	defer thorServer.Close()

	// Mock MayaChain server with available ARB.ETH pool
	// Note: Arbitrum's native gas token is ETH, so we look for ARB.ETH not ARB.ARB
	mayaServer := mockMayaPoolsServer(t, []map[string]interface{}{
		{"asset": "ARB.ETH", "status": "Available"},
	})
	defer mayaServer.Close()

	thorClient := thorchain.NewClient(thorServer.URL)
	mayaClient := mayachain.NewClient(mayaServer.URL)

	ctx := context.Background()
	// Bitcoin -> ARB native (MayaChain route)
	// Bitcoin has both Thor and Maya, but ARB is only on Maya
	// Native on Arbitrum = ETH (gas token), so we check ARB.ETH pool
	err := ValidateAssetRoute(ctx, thorClient, mayaClient, common.Bitcoin, common.Arbitrum, "")
	assert.NoError(t, err, "should find available pool on MayaChain")
}

func TestValidateAssetRoute_MayaPoolStaged(t *testing.T) {
	// Mock MayaChain server with staged ARB.ETH pool
	// Note: Arbitrum's native gas token is ETH, so we look for ARB.ETH not ARB.ARB
	mayaServer := mockMayaPoolsServer(t, []map[string]interface{}{
		{"asset": "ARB.ETH", "status": "Staged"},
	})
	defer mayaServer.Close()

	mayaClient := mayachain.NewClient(mayaServer.URL)

	ctx := context.Background()
	// Bitcoin -> ARB native where ARB.ETH is staged
	err := ValidateAssetRoute(ctx, nil, mayaClient, common.Bitcoin, common.Arbitrum, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "destination asset not available")
	assert.Contains(t, err.Error(), "MayaChain")
	assert.Contains(t, err.Error(), "Staged")
}

func TestValidateAssetRoute_TokenAvailable(t *testing.T) {
	// Mock MayaChain server with available USDC pool
	mayaServer := mockMayaPoolsServer(t, []map[string]interface{}{
		{"asset": "ARB.USDC-0XAF88D065E77C8CC2239327C5EDB3A432268E5831", "status": "Available"},
	})
	defer mayaServer.Close()

	mayaClient := mayachain.NewClient(mayaServer.URL)

	ctx := context.Background()
	// Bitcoin -> ARB USDC
	err := ValidateAssetRoute(ctx, nil, mayaClient, common.Bitcoin, common.Arbitrum, "0xaf88d065e77c8cc2239327c5edb3a432268e5831")
	assert.NoError(t, err, "should find available ARB USDC pool on MayaChain")
}

func mockThorPoolsServer(t *testing.T, pools []map[string]interface{}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/thorchain/pools" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(pools)
		require.NoError(t, err)
	}))
}

func mockMayaPoolsServer(t *testing.T, pools []map[string]interface{}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mayachain/pools" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(pools)
		require.NoError(t, err)
	}))
}
