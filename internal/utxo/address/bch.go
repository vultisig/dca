package address

import (
	bchchaincfg "github.com/gcash/bchd/chaincfg"
	bchtxscript "github.com/gcash/bchd/txscript"
	"github.com/gcash/bchutil"
)

// BCHAddress wraps a bchutil.Address to implement UTXOAddress.
type BCHAddress struct {
	addr bchutil.Address
}

// NewBCHAddress creates a BCHAddress from an address string.
func NewBCHAddress(addrStr string) (*BCHAddress, error) {
	addr, err := bchutil.DecodeAddress(addrStr, &bchchaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}
	return &BCHAddress{addr: addr}, nil
}

// NewBCHAddressFromPubKeyHash creates a BCHAddress from a pubkey hash.
// BCH doesn't have native SegWit, always P2PKH.
func NewBCHAddressFromPubKeyHash(pubKeyHash []byte) (*BCHAddress, error) {
	addr, err := bchutil.NewAddressPubKeyHash(pubKeyHash, &bchchaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}
	return &BCHAddress{addr: addr}, nil
}

func (a *BCHAddress) String() string        { return a.addr.String() }
func (a *BCHAddress) ScriptAddress() []byte { return a.addr.ScriptAddress() }
func (a *BCHAddress) PayToAddrScript() ([]byte, error) {
	return bchtxscript.PayToAddrScript(a.addr)
}

// Native returns the underlying bchutil.Address for BCH-specific operations.
func (a *BCHAddress) Native() bchutil.Address { return a.addr }
