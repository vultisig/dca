package thorchain

import (
	"context"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/vultisig/vultisig-go/common"
)

func makeThorAsset(ctx context.Context, client *Client, chain common.Chain, asset string) (string, error) {
	logrus.WithFields(logrus.Fields{
		"chain": chain.String(),
		"asset": asset,
	}).Debug("makeThorAsset called")

	thorNet, err := parseThorNetwork(chain)
	if err != nil {
		logrus.WithError(err).WithField("chain", chain.String()).Error("makeThorAsset: unsupported chain")
		return "", fmt.Errorf("unsupported chain: %w", err)
	}

	// Check if asset is native token
	if asset == "" {
		// Native token format: Network.TokenSymbol (e.g., AVAX.AVAX)
		nativeSymbol, er := chain.NativeSymbol()
		if er != nil {
			return "", fmt.Errorf("failed to get native symbol for chain %s: %w", chain, er)
		}
		return string(thorNet) + "." + nativeSymbol, nil
	}

	// For tokens, find the full asset string from THORChain pools
	// Format: Network.TokenSymbol-Asset (e.g., AVAX.SOL-0XFE6B19286885A4F7F55ADAD09C3CD1F906D2478F)
	pools, err := client.getPools(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get pools: %w", err)
	}

	networkPrefix := string(thorNet) + "."
	targetAsset := strings.ToUpper(asset)

	logrus.WithFields(logrus.Fields{
		"networkPrefix": networkPrefix,
		"targetAsset":   targetAsset,
		"poolCount":     len(pools),
	}).Debug("makeThorAsset: searching pools")

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

	logrus.WithFields(logrus.Fields{
		"chain":  thorNet,
		"asset":  asset,
		"target": targetAsset,
	}).Warn("makeThorAsset: asset not found in pools")
	return "", fmt.Errorf("asset not found in THORChain pools for chain %s and asset %s", thorNet, asset)
}
