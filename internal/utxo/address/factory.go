package address

import (
	"fmt"
	"log"

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
// Note: The segwit parameter is ignored for BCH and DOGE as these chains do not support SegWit.
// BCH uses CashAddr format (P2PKH only), and DOGE uses legacy P2PKH addresses.
func NewFromPubKeyHash(chain common.Chain, pubKeyHash []byte, segwit bool) (UTXOAddress, error) {
	switch chain {
	case common.Bitcoin:
		return NewBTCAddressFromPubKeyHash(pubKeyHash, segwit)
	case common.Litecoin:
		return NewLTCAddressFromPubKeyHash(pubKeyHash, segwit)
	case common.BitcoinCash:
		if segwit {
			log.Printf("[UTXO-ADDRESS] Warning: segwit=true ignored for %s - BCH does not support SegWit, using CashAddr P2PKH", chain.String())
		}
		return NewBCHAddressFromPubKeyHash(pubKeyHash)
	case common.Dogecoin:
		if segwit {
			log.Printf("[UTXO-ADDRESS] Warning: segwit=true ignored for %s - DOGE does not support SegWit, using legacy P2PKH", chain.String())
		}
		return NewDOGEAddressFromPubKeyHash(pubKeyHash)
	default:
		return nil, fmt.Errorf("unsupported UTXO chain: %s", chain)
	}
}
