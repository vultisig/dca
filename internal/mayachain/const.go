package mayachain

import (
	"fmt"

	"github.com/vultisig/vultisig-go/common"
)

const (
	DefaultStreamingInterval = "3"
	DefaultStreamingQuantity = "0"
)

func parseMayaNetwork(c common.Chain) (mayaNetwork, error) {
	switch c {
	case common.Bitcoin:
		return btc, nil
	case common.Ethereum:
		return eth, nil
	case common.Arbitrum:
		return arb, nil
	case common.Zcash:
		return zec, nil
	case common.Dash:
		return dash, nil
	case common.THORChain:
		return thor, nil
	default:
		return "", fmt.Errorf("unknown chain %s for MayaChain", c.String())
	}
}

type mayaNetwork string

const (
	btc  mayaNetwork = "BTC"
	eth  mayaNetwork = "ETH"
	arb  mayaNetwork = "ARB"
	zec  mayaNetwork = "ZEC"
	dash mayaNetwork = "DASH"
	thor mayaNetwork = "THOR"
)
