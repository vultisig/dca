package mayachain

import (
	"context"
	"fmt"
	"strings"

	"github.com/vultisig/vultisig-go/common"
)

const PoolStatusAvailable = "Available"

// ValidateAssetPool checks if a destination asset has an available pool on MayaChain.
// For native tokens (empty asset), it checks the chain's native pool (e.g., "BTC.BTC").
// For tokens, it searches for a matching pool by contract address.
func (c *Client) ValidateAssetPool(ctx context.Context, chain common.Chain, asset string) error {
	pools, err := c.getPools(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch pools: %w", err)
	}

	mayaNet, err := parseMayaNetwork(chain)
	if err != nil {
		return fmt.Errorf("chain not supported: %w", err)
	}

	networkPrefix := string(mayaNet) + "."

	// Native token check
	if asset == "" {
		// Get the chain's native symbol (e.g., ETH for Arbitrum, AVAX for Avalanche)
		nativeSymbol, err := chain.NativeSymbol()
		if err != nil {
			return fmt.Errorf("failed to get native symbol: %w", err)
		}
		nativeAsset := string(mayaNet) + "." + nativeSymbol
		for _, p := range pools {
			if p.Asset == nativeAsset {
				if p.Status != PoolStatusAvailable {
					return fmt.Errorf("pool %s is %s (not available)", p.Asset, p.Status)
				}
				return nil
			}
		}
		return fmt.Errorf("no pool found for native %s", mayaNet)
	}

	// Token check - find by address
	targetAddr := strings.ToUpper(asset)
	for _, p := range pools {
		if !strings.HasPrefix(p.Asset, networkPrefix) {
			continue
		}
		// Format: NETWORK.SYMBOL-ADDRESS
		if strings.HasSuffix(strings.ToUpper(p.Asset), "-"+targetAddr) {
			if p.Status != PoolStatusAvailable {
				return fmt.Errorf("pool %s is %s (not available)", p.Asset, p.Status)
			}
			return nil
		}
	}

	return fmt.Errorf("no pool found for %s on %s", asset, mayaNet)
}
