package evm

import (
	"github.com/vultisig/vultisig-go/common"
)

// SupportedEVMChains returns all EVM chains supported for recurring transactions
func SupportedEVMChains() []common.Chain {
	return []common.Chain{
		common.Ethereum,
		common.Base,
		common.BscChain,
		common.Avalanche,
		common.Arbitrum,
	}
}

// IsThorchainSupported checks if the chain is supported by THORChain for swaps
func IsThorchainSupported(chain common.Chain) bool {
	switch chain {
	case common.Ethereum, common.BscChain, common.Base, common.Avalanche:
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

