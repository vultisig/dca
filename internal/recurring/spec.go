package recurring

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
	common.Litecoin,
	common.Dogecoin,
	common.BitcoinCash,
	common.Solana,
	common.XRP,
	common.Zcash,
	common.GaiaChain,
	common.MayaChain,
	common.Tron,
}

const (
	startDate = "startDate"
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

func getMaxTxsForSend(chain common.Chain, token string, recipientCount int) uint32 {
	// Base transactions per recipient
	baseTxs := uint32(1)
	if chain == common.Solana && token != "" {
		// Solana SPL token transfers may need associated token account creation
		baseTxs = 2
	}
	// Multiply by number of recipients (one tx per recipient)
	return baseTxs * uint32(recipientCount)
}

func getMaxTxsForSwap(chain common.Chain) uint32 {
	switch {
	case chain == common.Solana:
		return 8
	case chain == common.XRP:
		return 1
	case chain == common.Zcash:
		return 1
	case chain == common.GaiaChain:
		return 1
	case chain == common.MayaChain:
		return 1
	case chain == common.Tron:
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
