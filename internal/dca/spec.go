package dca

import (
	"fmt"

	"github.com/vultisig/vultisig-go/common"
)

const (
	PluginRecurringSends = "vultisig-recurring-sends-0000"
	PluginRecurringSwaps = "vultisig-dca-0000"
)

var supportedChains = []common.Chain{
	common.Ethereum,
	common.Arbitrum,
	common.Avalanche,
	common.BscChain,
	common.Base,
	common.Blast,
	common.Optimism,
	common.Polygon,
	common.Bitcoin,
	common.Solana,
	common.XRP,
	common.Zcash,
}

const (
	endDate   = "endDate"
	frequency = "frequency"

	onetime  = "one-time"
	minutely = "minutely"
	hourly   = "hourly"
	daily    = "daily"
	weekly   = "weekly"
	biWeekly = "bi-weekly"
	monthly  = "monthly"
)

func getRateLimitWindow(freq string) (uint32, error) {
	switch freq {
	case onetime:
		return 60, nil
	case minutely:
		return 60, nil
	case hourly:
		return 3600, nil
	case daily:
		return 86400, nil
	case weekly:
		return 604800, nil
	case biWeekly:
		return 1209600, nil
	case monthly:
		return 2592000, nil
	default:
		return 0, fmt.Errorf("unknown frequency: %s", freq)
	}
}

func getMaxTxsForSend(chain common.Chain, token string) uint32 {
	if chain == common.Solana && token != "" {
		return 2
	}
	return 1
}

func getMaxTxsForSwap(chain common.Chain) uint32 {
	switch {
	case chain == common.Solana:
		return 8
	case chain == common.XRP:
		return 1
	case chain == common.Zcash:
		return 1
	case chain.IsEvm():
		return 2
	default:
		return 1
	}
}

func getSupportedChainStrings() []string {
	var cc []string
	for _, c := range supportedChains {
		cc = append(cc, c.String())
	}
	return cc
}
