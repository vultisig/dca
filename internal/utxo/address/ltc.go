package address

import (
	ltcchaincfg "github.com/ltcsuite/ltcd/chaincfg"
	"github.com/ltcsuite/ltcd/ltcutil"
	ltctxscript "github.com/ltcsuite/ltcd/txscript"
)

// LTCAddress wraps a ltcutil.Address to implement UTXOAddress.
type LTCAddress struct {
	addr ltcutil.Address
}

// NewLTCAddress creates a LTCAddress from an address string.
func NewLTCAddress(addrStr string) (*LTCAddress, error) {
	addr, err := ltcutil.DecodeAddress(addrStr, &ltcchaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}
	return &LTCAddress{addr: addr}, nil
}

// NewLTCAddressFromPubKeyHash creates a LTCAddress from a pubkey hash.
func NewLTCAddressFromPubKeyHash(pubKeyHash []byte, segwit bool) (*LTCAddress, error) {
	var addr ltcutil.Address
	var err error
	if segwit {
		addr, err = ltcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &ltcchaincfg.MainNetParams)
	} else {
		addr, err = ltcutil.NewAddressPubKeyHash(pubKeyHash, &ltcchaincfg.MainNetParams)
	}
	if err != nil {
		return nil, err
	}
	return &LTCAddress{addr: addr}, nil
}

func (a *LTCAddress) String() string        { return a.addr.String() }
func (a *LTCAddress) ScriptAddress() []byte { return a.addr.ScriptAddress() }
func (a *LTCAddress) PayToAddrScript() ([]byte, error) {
	return ltctxscript.PayToAddrScript(a.addr)
}

// Native returns the underlying ltcutil.Address for LTC-specific operations.
func (a *LTCAddress) Native() ltcutil.Address { return a.addr }
