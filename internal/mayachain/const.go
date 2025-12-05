package mayachain

import (
	"errors"

	"github.com/vultisig/vultisig-go/common"
)

const (
	defaultStreamingInterval = "3"
	defaultStreamingQuantity = "0"
)

func parseMayaNetwork(c common.Chain) (mayaNetwork, error) {
	switch c {
	case common.Bitcoin:
		return btc, nil
	case common.Ethereum:
		return eth, nil
	case common.Zcash:
		return zec, nil
	case common.Dash:
		return dash, nil
	case common.THORChain:
		return thor, nil
	default:
		return "", errors.New("unknown chain for MayaChain")
	}
}

type mayaNetwork string

const (
	btc  mayaNetwork = "BTC"
	eth  mayaNetwork = "ETH"
	zec  mayaNetwork = "ZEC"
	dash mayaNetwork = "DASH"
	thor mayaNetwork = "THOR"
)
