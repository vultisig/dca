package util

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/vultisig/vultisig-go/common"
)

// NativeDecimals maps chain to native token decimals
var NativeDecimals = map[common.Chain]int{
	common.Ethereum:  18,
	common.Arbitrum:  18,
	common.Avalanche: 18,
	common.Base:      18,
	common.Blast:     18,
	common.Optimism:  18,
	common.Polygon:   18,
	common.Bitcoin:   8,
	common.Solana:    9,
	common.XRP:       6,
	common.Zcash:     8,
}

// GetNativeDecimals returns the native token decimals for a chain
func GetNativeDecimals(chain common.Chain) (int, error) {
	decimals, ok := NativeDecimals[chain]
	if !ok {
		return 0, fmt.Errorf("unknown chain: %s", chain.String())
	}
	return decimals, nil
}

// IsNativeToken checks if the token address represents a native token
func IsNativeToken(token string) bool {
	return token == "" || strings.EqualFold(token, "native")
}

// ToBaseUnits converts a human-readable amount to base units
// e.g., "10" USDC (6 decimals) -> "10000000"
func ToBaseUnits(amount string, decimals int) (*big.Int, error) {
	if amount == "" {
		return nil, fmt.Errorf("amount cannot be empty")
	}

	// Handle negative numbers
	negative := false
	if strings.HasPrefix(amount, "-") {
		negative = true
		amount = amount[1:]
	}

	// Split into whole and fractional parts
	parts := strings.Split(amount, ".")
	whole := parts[0]
	frac := ""
	if len(parts) > 1 {
		frac = parts[1]
	} else if len(parts) > 2 {
		return nil, fmt.Errorf("invalid amount format: %s", amount)
	}

	// Pad or truncate fractional part to decimals length
	if len(frac) < decimals {
		frac += strings.Repeat("0", decimals-len(frac))
	} else if len(frac) > decimals {
		frac = frac[:decimals]
	}

	// Combine whole and fractional parts
	combined := whole + frac

	// Remove leading zeros (but keep at least one digit)
	combined = strings.TrimLeft(combined, "0")
	if combined == "" {
		combined = "0"
	}

	result, ok := new(big.Int).SetString(combined, 10)
	if !ok {
		return nil, fmt.Errorf("invalid amount: %s", amount)
	}

	if negative {
		result.Neg(result)
	}

	return result, nil
}

// FromBaseUnits converts base units to a human-readable amount
// e.g., "10000000" with 6 decimals -> "10"
func FromBaseUnits(amount *big.Int, decimals int) string {
	if amount == nil {
		return "0"
	}

	str := amount.String()
	negative := false
	if strings.HasPrefix(str, "-") {
		negative = true
		str = str[1:]
	}

	// Pad with leading zeros if needed
	if len(str) <= decimals {
		str = strings.Repeat("0", decimals-len(str)+1) + str
	}

	// Insert decimal point
	insertPos := len(str) - decimals
	whole := str[:insertPos]
	frac := str[insertPos:]

	// Remove trailing zeros from fractional part
	frac = strings.TrimRight(frac, "0")

	var result string
	if frac == "" {
		result = whole
	} else {
		result = whole + "." + frac
	}

	if negative {
		result = "-" + result
	}

	return result
}
