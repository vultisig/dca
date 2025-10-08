package xrp

import (
	"github.com/vultisig/vultisig-go/common"
)

type From struct {
	Address  string
	Amount   uint64 // XRP drops (1 XRP = 1,000,000 drops)
	Sequence uint32 // Will be auto-fetched by provider
	PubKey   string // Child-derived pubkey for SigningPubKey field
}

// To destination could be any supported chain
type To struct {
	Chain   common.Chain
	AssetID string
	Address string
}