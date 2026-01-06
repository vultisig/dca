package dash

import (
	"fmt"
	"math"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// SendService handles building Dash send transactions
type SendService struct{}

// NewSendService creates a new SendService
func NewSendService() *SendService {
	return &SendService{}
}

// BuildTransfer builds transaction outputs for a Dash transfer.
// Returns the outputs and the index of the change output.
func (s *SendService) BuildTransfer(
	toAddress string,
	fromAddress btcutil.Address,
	amount uint64,
) ([]*wire.TxOut, int, error) {
	// Create script for destination address
	toScript, err := createDashScript(toAddress)
	if err != nil {
		return nil, 0, fmt.Errorf("dash: failed to create to script: %w", err)
	}

	// Create script for change address using the same Dash-specific logic
	// to ensure consistent handling of Dash address versions
	changeScript, err := createDashScript(fromAddress.String())
	if err != nil {
		return nil, 0, fmt.Errorf("dash: failed to create change script: %w", err)
	}

	// Validate amount won't overflow int64
	if amount > math.MaxInt64 {
		return nil, 0, fmt.Errorf("dash: amount %d exceeds maximum int64 value", amount)
	}

	outputs := []*wire.TxOut{
		{
			Value:    int64(amount),
			PkScript: toScript,
		},
		{
			Value:    0, // Change amount calculated by signer
			PkScript: changeScript,
		},
	}

	changeOutputIndex := 1

	return outputs, changeOutputIndex, nil
}

// createDashScript creates a P2PKH or P2SH script for a Dash address
func createDashScript(address string) ([]byte, error) {
	if len(address) == 0 {
		return nil, fmt.Errorf("dash: empty address")
	}

	// Decode Base58Check address
	decoded, version, err := base58.CheckDecode(address)
	if err != nil {
		return nil, fmt.Errorf("dash: failed to decode address: %w", err)
	}

	if len(decoded) != 20 {
		return nil, fmt.Errorf("dash: invalid address hash length: expected 20 bytes, got %d", len(decoded))
	}

	// Dash address versions:
	// 0x4C (76) - P2PKH mainnet (starts with 'X')
	// 0x10 (16) - P2SH mainnet (starts with '7')
	switch version {
	case 0x4C: // P2PKH
		return createP2PKHScript(decoded)
	case 0x10: // P2SH
		return createP2SHScript(decoded)
	default:
		return nil, fmt.Errorf("dash: unknown address version: 0x%02x", version)
	}
}

// createP2PKHScript creates a P2PKH script from a 20-byte public key hash
func createP2PKHScript(pubKeyHash []byte) ([]byte, error) {
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_DUP)
	builder.AddOp(txscript.OP_HASH160)
	builder.AddData(pubKeyHash)
	builder.AddOp(txscript.OP_EQUALVERIFY)
	builder.AddOp(txscript.OP_CHECKSIG)
	return builder.Script()
}

// createP2SHScript creates a P2SH script from a 20-byte script hash
func createP2SHScript(scriptHash []byte) ([]byte, error) {
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_HASH160)
	builder.AddData(scriptHash)
	builder.AddOp(txscript.OP_EQUAL)
	return builder.Script()
}

// DecodeAddress decodes a Dash address string to a btcutil.Address
func DecodeAddress(address string) (btcutil.Address, error) {
	if len(address) == 0 {
		return nil, fmt.Errorf("dash: empty address")
	}

	decoded, version, err := base58.CheckDecode(address)
	if err != nil {
		return nil, fmt.Errorf("dash: failed to decode address: %w", err)
	}

	if len(decoded) != 20 {
		return nil, fmt.Errorf("dash: invalid address hash length: expected 20 bytes, got %d", len(decoded))
	}

	// Create appropriate address type based on version
	switch version {
	case 0x4C: // P2PKH mainnet
		return btcutil.NewAddressPubKeyHash(decoded, &DashMainNetParams)
	case 0x10: // P2SH mainnet
		return btcutil.NewAddressScriptHashFromHash(decoded, &DashMainNetParams)
	default:
		return nil, fmt.Errorf("dash: unknown address version: 0x%02x", version)
	}
}

