package maya

import (
	"github.com/vultisig/vultisig-go/common"
)

// From represents the source of a MayaChain transaction
type From struct {
	Address        string
	AssetID        string // Asset identifier (empty string for native CACAO)
	Amount         uint64 // CACAO in smallest unit
	PubKey         string // Child-derived pubkey for signing (hex encoded)
	AccountNumber  uint64 // Account number from chain
	Sequence       uint64 // Account sequence number
}

// To represents the destination of a MayaChain transaction
type To struct {
	Chain   common.Chain
	AssetID string
	Address string
}

