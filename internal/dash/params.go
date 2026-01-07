package dash

import "github.com/btcsuite/btcd/chaincfg"

// DashMainNetParams defines the network parameters for Dash mainnet
// These are similar to Bitcoin but with different address prefixes
var DashMainNetParams = chaincfg.Params{
	Name: "mainnet",
	Net:  0xbf0c6bbd, // Dash mainnet magic bytes

	// Address encoding magic bytes
	PubKeyHashAddrID: 0x4C, // P2PKH addresses start with 'X'
	ScriptHashAddrID: 0x10, // P2SH addresses start with '7'
	PrivateKeyID:     0xCC, // WIF private keys start with '7' or 'X'

	// BIP32 hierarchical deterministic extended key magic bytes
	HDPrivateKeyID: [4]byte{0x04, 0x88, 0xAD, 0xE4}, // xprv
	HDPublicKeyID:  [4]byte{0x04, 0x88, 0xB2, 0x1E}, // xpub

	// Human-readable part for Bech32 encoded segwit addresses
	// Dash doesn't use Bech32, but this field is required
	Bech32HRPSegwit: "dash",

	// Coin type for BIP44
	HDCoinType: 5, // Dash is coin type 5
}

