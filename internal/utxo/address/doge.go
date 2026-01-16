package address

import (
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

// DogeMainNetParams defines Dogecoin mainnet parameters.
var DogeMainNetParams = chaincfg.Params{
	Name:             "mainnet",
	Net:              0xc0c0c0c0,
	PubKeyHashAddrID: 0x1E, // D prefix
	ScriptHashAddrID: 0x16, // 9 or A prefix
}

// DOGEAddress wraps a btcutil.Address to implement UTXOAddress for Dogecoin.
type DOGEAddress struct {
	addr btcutil.Address
}

// NewDOGEAddress creates a DOGEAddress from an address string.
func NewDOGEAddress(addrStr string) (*DOGEAddress, error) {
	addr, err := btcutil.DecodeAddress(addrStr, &DogeMainNetParams)
	if err != nil {
		return nil, err
	}
	return &DOGEAddress{addr: addr}, nil
}

// NewDOGEAddressFromPubKeyHash creates a DOGEAddress from a pubkey hash.
// DOGE doesn't have native SegWit, always P2PKH.
func NewDOGEAddressFromPubKeyHash(pubKeyHash []byte) (*DOGEAddress, error) {
	addr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, &DogeMainNetParams)
	if err != nil {
		return nil, err
	}
	return &DOGEAddress{addr: addr}, nil
}

func (a *DOGEAddress) String() string        { return a.addr.String() }
func (a *DOGEAddress) ScriptAddress() []byte { return a.addr.ScriptAddress() }
func (a *DOGEAddress) PayToAddrScript() ([]byte, error) {
	return txscript.PayToAddrScript(a.addr)
}

// Native returns the underlying btcutil.Address for DOGE-specific operations.
func (a *DOGEAddress) Native() btcutil.Address { return a.addr }
