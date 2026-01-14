package address

import (
	"fmt"

	"github.com/vultisig/vultisig-go/common"
)

// NewFromString creates a UTXOAddress from an address string based on chain.
func NewFromString(chain common.Chain, addrStr string) (UTXOAddress, error) {
	switch chain {
	case common.Bitcoin:
		return NewBTCAddress(addrStr)
	case common.Litecoin:
		return NewLTCAddress(addrStr)
	case common.BitcoinCash:
		return NewBCHAddress(addrStr)
	case common.Dogecoin:
		return NewDOGEAddress(addrStr)
	default:
		return nil, fmt.Errorf("unsupported UTXO chain: %s", chain)
	}
}

// NewFromPubKeyHash creates a UTXOAddress from a pubkey hash based on chain.
func NewFromPubKeyHash(chain common.Chain, pubKeyHash []byte, segwit bool) (UTXOAddress, error) {
	switch chain {
	case common.Bitcoin:
		return NewBTCAddressFromPubKeyHash(pubKeyHash, segwit)
	case common.Litecoin:
		return NewLTCAddressFromPubKeyHash(pubKeyHash, segwit)
	case common.BitcoinCash:
		return NewBCHAddressFromPubKeyHash(pubKeyHash)
	case common.Dogecoin:
		return NewDOGEAddressFromPubKeyHash(pubKeyHash)
	default:
		return nil, fmt.Errorf("unsupported UTXO chain: %s", chain)
	}
}
