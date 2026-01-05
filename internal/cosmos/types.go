package cosmos

import (
	"github.com/vultisig/vultisig-go/common"
)

// From represents the source of a Cosmos transaction
type From struct {
	Address        string
	AssetID        string // Asset identifier (empty string for native ATOM)
	Amount         uint64 // ATOM in uatom (1 ATOM = 1,000,000 uatom)
	PubKey         string // Child-derived pubkey for signing (hex encoded)
	AccountNumber  uint64 // Account number from chain
	Sequence       uint64 // Account sequence number
}

// To represents the destination of a Cosmos transaction
type To struct {
	Chain   common.Chain
	AssetID string
	Address string
}

