package evm

import (
	"context"
	"math/big"
	"testing"

	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/vultisig/vultisig-go/common"
)

func TestIsThorchainSupported(t *testing.T) {
	tests := []struct {
		chain    common.Chain
		expected bool
	}{
		{common.Ethereum, true},
		{common.BscChain, true},
		{common.Base, true},
		{common.Avalanche, true},
		{common.Arbitrum, false}, // Arbitrum is MayaChain only
		{common.Optimism, false},
		{common.Polygon, false},
		{common.Solana, false},
		{common.Bitcoin, false},
	}

	for _, tt := range tests {
		t.Run(tt.chain.String(), func(t *testing.T) {
			result := IsThorchainSupported(tt.chain)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestIsMayachainSupported(t *testing.T) {
	tests := []struct {
		chain    common.Chain
		expected bool
	}{
		{common.Arbitrum, true},  // ARB is MayaChain only
		{common.Ethereum, false}, // ETH routes through THORChain
		{common.BscChain, false},
		{common.Base, false},
		{common.Avalanche, false},
		{common.Optimism, false},
		{common.Polygon, false},
		{common.Solana, false},
		{common.Bitcoin, false},
	}

	for _, tt := range tests {
		t.Run(tt.chain.String(), func(t *testing.T) {
			result := IsMayachainSupported(tt.chain)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestSupportedEVMChains(t *testing.T) {
	chains := SupportedEVMChains()

	// Should contain exactly 10 chains
	require.Len(t, chains, 10)

	// Check that all expected chains are present
	chainSet := make(map[common.Chain]bool)
	for _, c := range chains {
		chainSet[c] = true
	}

	require.True(t, chainSet[common.Ethereum], "Ethereum should be supported")
	require.True(t, chainSet[common.Arbitrum], "Arbitrum should be supported")
	require.True(t, chainSet[common.Avalanche], "Avalanche should be supported")
	require.True(t, chainSet[common.BscChain], "BSC should be supported")
	require.True(t, chainSet[common.Base], "Base should be supported")
	require.True(t, chainSet[common.Blast], "Blast should be supported")
	require.True(t, chainSet[common.CronosChain], "Cronos should be supported")
	require.True(t, chainSet[common.Optimism], "Optimism should be supported")
	require.True(t, chainSet[common.Polygon], "Polygon should be supported")
	require.True(t, chainSet[common.Zksync], "zkSync should be supported")
}

// MockProvider implements Provider interface for testing
type MockProvider struct {
	amountOut *big.Int
	tx        []byte
	err       error
}

func (m *MockProvider) MakeTx(ctx context.Context, from From, to To) (*big.Int, []byte, error) {
	return m.amountOut, m.tx, m.err
}

func TestSwapService_FindBestAmountOut(t *testing.T) {
	ctx := context.Background()

	from := From{
		Chain:   common.Ethereum,
		AssetID: ecommon.Address{},
		Address: ecommon.HexToAddress("0x1111111111111111111111111111111111111111"),
		Amount:  big.NewInt(1000000000000000000),
	}

	to := To{
		Chain:   common.Bitcoin,
		AssetID: "",
		Address: "bc1qexample",
	}

	t.Run("selects provider with best amount out", func(t *testing.T) {
		provider1 := &MockProvider{
			amountOut: big.NewInt(100),
			tx:        []byte{0x01},
			err:       nil,
		}
		provider2 := &MockProvider{
			amountOut: big.NewInt(200), // Better
			tx:        []byte{0x02},
			err:       nil,
		}

		service := newSwapService([]Provider{provider1, provider2})
		tx, err := service.FindBestAmountOut(ctx, from, to)

		require.NoError(t, err)
		require.Equal(t, []byte{0x02}, tx) // Should select provider2's tx
	})

	t.Run("returns error when no providers", func(t *testing.T) {
		service := newSwapService([]Provider{})
		_, err := service.FindBestAmountOut(ctx, from, to)

		require.Error(t, err)
		require.Contains(t, err.Error(), "no providers available")
	})

	t.Run("falls back to working provider when one fails", func(t *testing.T) {
		failingProvider := &MockProvider{
			amountOut: nil,
			tx:        nil,
			err:       context.DeadlineExceeded,
		}
		workingProvider := &MockProvider{
			amountOut: big.NewInt(100),
			tx:        []byte{0x01},
			err:       nil,
		}

		service := newSwapService([]Provider{failingProvider, workingProvider})
		tx, err := service.FindBestAmountOut(ctx, from, to)

		require.NoError(t, err)
		require.Equal(t, []byte{0x01}, tx)
	})

	t.Run("returns error when all providers fail", func(t *testing.T) {
		failingProvider1 := &MockProvider{err: context.DeadlineExceeded}
		failingProvider2 := &MockProvider{err: context.Canceled}

		service := newSwapService([]Provider{failingProvider1, failingProvider2})
		_, err := service.FindBestAmountOut(ctx, from, to)

		require.Error(t, err)
		require.Contains(t, err.Error(), "all providers failed")
	})
}

func TestChainProviderMapping(t *testing.T) {
	// Test that each supported chain has the correct provider(s)
	// ETH/BSC/BASE/AVAX route through THORChain
	// ARB routes through MayaChain
	// Other chains support direct sends only
	tests := []struct {
		chain        common.Chain
		hasThorchain bool
		hasMayachain bool
		description  string
	}{
		{common.Ethereum, true, false, "ETH supported by THORChain only"},
		{common.Base, true, false, "Base supported by THORChain only"},
		{common.BscChain, true, false, "BSC supported by THORChain only"},
		{common.Avalanche, true, false, "AVAX supported by THORChain only"},
		{common.Arbitrum, false, true, "ARB supported by MayaChain only"},
		{common.Blast, false, false, "Blast - sends only, no swap routing"},
		{common.CronosChain, false, false, "Cronos - sends only, no swap routing"},
		{common.Optimism, false, false, "Optimism - sends only, no swap routing"},
		{common.Polygon, false, false, "Polygon - sends only, no swap routing"},
		{common.Zksync, false, false, "zkSync - sends only, no swap routing"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			require.Equal(t, tt.hasThorchain, IsThorchainSupported(tt.chain))
			require.Equal(t, tt.hasMayachain, IsMayachainSupported(tt.chain))
		})
	}
}



