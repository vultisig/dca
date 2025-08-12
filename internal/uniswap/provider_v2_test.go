package uniswap

import (
	"math/big"
	"testing"
)

func TestTruncSlippage(t *testing.T) {
	tests := []struct {
		name         string
		amount       *big.Int
		slippageBips uint64
		expected     *big.Int
	}{
		{
			name:         "5% slippage (500 bips)",
			amount:       big.NewInt(1000),
			slippageBips: 500,
			expected:     big.NewInt(950),
		},
		{
			name:         "fractional result",
			amount:       big.NewInt(999),
			slippageBips: 100,             // 1%
			expected:     big.NewInt(989), // 999 * 0.99 = 989.01, truncated to 989
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deductSlippage(tt.amount, tt.slippageBips)
			if result.Cmp(tt.expected) != 0 {
				t.Errorf("deductSlippage(%v, %v) = %v, expected %v",
					tt.amount, tt.slippageBips, result, tt.expected)
			}
		})
	}
}
