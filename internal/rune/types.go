package rune

import (
	"github.com/vultisig/vultisig-go/common"
)

// From represents the source of a THORChain transaction
type From struct {
	Address       string
	AssetID       string // Asset identifier (empty string for native RUNE)
	Amount        uint64 // RUNE in base units (1 RUNE = 100,000,000 base units)
	PubKey        string // Child-derived pubkey for signing (hex encoded)
	AccountNumber uint64 // Account number from chain
	Sequence      uint64 // Account sequence number
}

// To represents the destination of a THORChain transaction
type To struct {
	Chain   common.Chain
	AssetID string
	Address string
}

