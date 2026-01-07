package tron

import (
	"github.com/vultisig/vultisig-go/common"
)

// From represents the source of a TRON transaction
type From struct {
	Address string
	AssetID string // Asset identifier (empty string for native TRX)
	Amount  uint64 // TRX in sun (1 TRX = 1,000,000 sun)
	PubKey  string // Child-derived pubkey for signing
}

// To represents the destination of a TRON transaction
type To struct {
	Chain   common.Chain
	AssetID string
	Address string
}

