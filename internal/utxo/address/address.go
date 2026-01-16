package address

// UTXOAddress is a chain-agnostic address interface for UTXO chains.
// Each chain implements this using its native library (btcutil, ltcutil, bchutil).
type UTXOAddress interface {
	// String returns the human-readable address (chain-specific encoding)
	// e.g., "bc1q...", "ltc1q...", "bitcoincash:q...", "D..."
	String() string

	// ScriptAddress returns the raw bytes (20-byte pubkey hash or script hash)
	// This is chain-agnostic - the same pubkey produces the same bytes on all chains
	ScriptAddress() []byte

	// PayToAddrScript generates the scriptPubKey for paying to this address
	// Uses the chain's native txscript library internally
	PayToAddrScript() ([]byte, error)
}
