package mayachain

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vultisig/vultisig-go/common"
)

func TestValidateAssetPool_NativeAvailable(t *testing.T) {
	pools := poolsResponse{
		{Asset: "BTC.BTC", Status: "Available"},
		{Asset: "ETH.ETH", Status: "Available"},
	}
	server := mockPoolsServer(t, pools)
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()

	err := client.ValidateAssetPool(ctx, common.Bitcoin, "")
	assert.NoError(t, err, "native BTC should be available")
}

func TestValidateAssetPool_NativeStaged(t *testing.T) {
	pools := poolsResponse{
		{Asset: "ARB.ARB", Status: "Staged"},
	}
	server := mockPoolsServer(t, pools)
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()

	err := client.ValidateAssetPool(ctx, common.Arbitrum, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Staged")
	assert.Contains(t, err.Error(), "not available")
}

func TestValidateAssetPool_NativeNotFound(t *testing.T) {
	pools := poolsResponse{
		{Asset: "ETH.ETH", Status: "Available"},
	}
	server := mockPoolsServer(t, pools)
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()

	err := client.ValidateAssetPool(ctx, common.Arbitrum, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no pool found for native ARB")
}

func TestValidateAssetPool_TokenAvailable(t *testing.T) {
	pools := poolsResponse{
		{Asset: "ETH.ETH", Status: "Available"},
		{Asset: "ETH.USDC-0XA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48", Status: "Available"},
	}
	server := mockPoolsServer(t, pools)
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()

	// Test with lowercase address (should match case-insensitively)
	err := client.ValidateAssetPool(ctx, common.Ethereum, "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
	assert.NoError(t, err, "ETH USDC should be available")
}

func TestValidateAssetPool_TokenNotFound(t *testing.T) {
	pools := poolsResponse{
		{Asset: "ETH.ETH", Status: "Available"},
	}
	server := mockPoolsServer(t, pools)
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()

	err := client.ValidateAssetPool(ctx, common.Ethereum, "0x1234567890123456789012345678901234567890")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no pool found for")
}

func TestValidateAssetPool_UnsupportedChain(t *testing.T) {
	pools := poolsResponse{}
	server := mockPoolsServer(t, pools)
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()

	err := client.ValidateAssetPool(ctx, common.Solana, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "chain not supported")
}

// Integration test - skipped by default, run with -run TestValidateAssetPool_Integration
func TestValidateAssetPool_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client := NewClient("https://mayanode.mayachain.info")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Test native BTC - should be available
	err := client.ValidateAssetPool(ctx, common.Bitcoin, "")
	assert.NoError(t, err, "native BTC should have available pool on MayaChain")

	// Test native ETH - should be available
	err = client.ValidateAssetPool(ctx, common.Ethereum, "")
	assert.NoError(t, err, "native ETH should have available pool on MayaChain")

	// Test ARB native - might be Staged (this is the problem case)
	err = client.ValidateAssetPool(ctx, common.Arbitrum, "")
	// Log the result for diagnostic purposes
	if err != nil {
		t.Logf("ARB native pool status: %v", err)
	} else {
		t.Logf("ARB native pool is available")
	}
}

func mockPoolsServer(t *testing.T, pools poolsResponse) *httptest.Server {
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
