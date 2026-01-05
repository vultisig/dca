package evm

import (
	"github.com/vultisig/vultisig-go/common"
)

// SupportedEVMChains returns all EVM chains supported for recurring transactions
func SupportedEVMChains() []common.Chain {
	return []common.Chain{
		common.Ethereum,
		common.Arbitrum,
		common.Avalanche,
		common.BscChain,
		common.Base,
		common.Blast,
		common.CronosChain,
		common.Optimism,
		common.Polygon,
		common.Zksync,
	}
}

// IsThorchainSupported checks if the chain is supported by THORChain for swaps
// THORChain supports: ETH, BSC, BASE, AVAX
func IsThorchainSupported(chain common.Chain) bool {
	switch chain {
	case common.Ethereum, common.BscChain, common.Base, common.Avalanche:
		return true
	default:
		return false
	}
}

// IsDirectSendSupported checks if the chain supports direct sends (no swap routing needed)
// All EVM chains support native sends
func IsDirectSendSupported(chain common.Chain) bool {
	switch chain {
	case common.Ethereum, common.Arbitrum, common.Avalanche, common.BscChain,
		common.Base, common.Blast, common.CronosChain, common.Optimism,
		common.Polygon, common.Zksync:
		return true
	default:
		return false
	}
}

// IsMayachainSupported checks if the chain is supported by MayaChain for swaps
func IsMayachainSupported(chain common.Chain) bool {
	switch chain {
	case common.Arbitrum:
		return true
	default:
		return false
	}
}

