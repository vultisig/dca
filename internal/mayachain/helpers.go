package mayachain

import (
	"context"
	"fmt"
	"strings"

	"github.com/vultisig/vultisig-go/common"
)

func makeMayaAsset(ctx context.Context, client *Client, chain common.Chain, asset string) (string, error) {
	mayaNet, err := parseMayaNetwork(chain)
	if err != nil {
		return "", fmt.Errorf("unsupported chain: %w", err)
	}

	// Check if asset is native token
	if asset == "" {
		// Native token format: Network.TokenSymbol (e.g., ZEC.ZEC)
		nativeSymbol, er := chain.NativeSymbol()
		if er != nil {
			return "", fmt.Errorf("failed to get native symbol for chain %s: %w", chain, er)
		}
		return string(mayaNet) + "." + nativeSymbol, nil
	}

	// For tokens, find the full asset string from MayaChain pools
	pools, err := client.getPools(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get pools: %w", err)
	}

	networkPrefix := string(mayaNet) + "."
	targetAsset := strings.ToUpper(asset)

	for _, pp := range pools {
		// Check if pool belongs to our network
		if !strings.HasPrefix(pp.Asset, networkPrefix) {
			continue
		}

		// Split the asset into parts: Network.TokenSymbol-Asset
		parts := strings.Split(pp.Asset, ".")
		if len(parts) != 2 {
			continue
		}

		// Check if the second part contains a dash (indicating token with address)
		tokenPart := parts[1]
		if !strings.Contains(tokenPart, "-") {
			continue
		}

		// Split token part: TokenSymbol-Address
		tokenParts := strings.Split(tokenPart, "-")
		if len(tokenParts) != 2 {
			continue
		}

		// Check if the address matches (case-insensitive)
		poolAddress := tokenParts[1]
		if strings.EqualFold(poolAddress, targetAsset) {
			return pp.Asset, nil
		}
	}

	return "", fmt.Errorf("asset not found in MayaChain pools for chain %s and asset %s", mayaNet, asset)
}
