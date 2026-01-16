package address

import (
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

// BTCAddress wraps a btcutil.Address to implement UTXOAddress.
type BTCAddress struct {
	addr btcutil.Address
}

// NewBTCAddress creates a BTCAddress from an address string.
func NewBTCAddress(addrStr string) (*BTCAddress, error) {
	addr, err := btcutil.DecodeAddress(addrStr, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}
	return &BTCAddress{addr: addr}, nil
}

// NewBTCAddressFromPubKeyHash creates a BTCAddress from a pubkey hash.
func NewBTCAddressFromPubKeyHash(pubKeyHash []byte, segwit bool) (*BTCAddress, error) {
	var addr btcutil.Address
	var err error
	if segwit {
		addr, err = btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	} else {
		addr, err = btcutil.NewAddressPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	}
	if err != nil {
		return nil, err
	}
	return &BTCAddress{addr: addr}, nil
}

func (a *BTCAddress) String() string        { return a.addr.String() }
func (a *BTCAddress) ScriptAddress() []byte { return a.addr.ScriptAddress() }
func (a *BTCAddress) PayToAddrScript() ([]byte, error) {
	return txscript.PayToAddrScript(a.addr)
}

// Native returns the underlying btcutil.Address for BTC-specific operations.
func (a *BTCAddress) Native() btcutil.Address { return a.addr }
