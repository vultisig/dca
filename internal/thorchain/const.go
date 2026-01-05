package thorchain

import (
	"errors"

	"github.com/vultisig/vultisig-go/common"
)

const (
	defaultStreamingInterval = "3"
	defaultStreamingQuantity = "0"
	defaultToleranceBps      = "2500"
)

func parseThorNetwork(c common.Chain) (thorNetwork, error) {
	switch c {
	case common.Bitcoin:
		return btc, nil
	case common.Ethereum:
		return eth, nil
	case common.BscChain:
		return bsc, nil
	case common.Base:
		return base, nil
	case common.Avalanche:
		return avax, nil
	case common.XRP:
		return xrp, nil
	default:
		return "", errors.New("unknown chain")
	}
}

// IsThorChainSupported checks if all provided chains are supported by the
// THORChain router for cross-chain swaps.
func IsThorChainSupported(chains ...common.Chain) bool {
	for _, c := range chains {
		if _, err := parseThorNetwork(c); err != nil {
			return false
		}
	}
	return true
}

type thorNetwork string

const (
	btc  thorNetwork = "BTC"
	eth  thorNetwork = "ETH"
	bsc  thorNetwork = "BSC"
	base thorNetwork = "BASE"
	avax thorNetwork = "AVAX"
	xrp  thorNetwork = "XRP"
)
