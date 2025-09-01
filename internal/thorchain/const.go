package thorchain

import (
	"errors"

	"github.com/vultisig/vultisig-go/common"
)

const (
	defaultStreamingInterval = "3"
	defaultStreamingQuantity = "0"
	defaultToleranceBps      = "300"
)

func toThor(c common.Chain) (thorNetwork, error) {
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
	default:
		return "", errors.New("unknown chain")
	}
}

type thorNetwork string

const (
	btc  thorNetwork = "BTC"
	eth  thorNetwork = "ETH"
	bsc  thorNetwork = "BSC"
	base thorNetwork = "BASE"
	avax thorNetwork = "AVAX"
)

var networks = []thorNetwork{
	btc,
	eth,
	bsc,
	base,
	avax,
}
