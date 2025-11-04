package thorchain_native

import (
	"github.com/vultisig/vultisig-go/common"
)

type From struct {
	Address  string // THORChain address (thor1...)
	AssetID  string // Asset identifier ("" for native RUNE, or token symbol)
	Amount   uint64 // Amount in base units (1e8 for RUNE)
	Sequence uint64 // Account sequence (Cosmos SDK style)
	PubKey   string // Child-derived public key for signing
}

// To destination could be any supported chain
type To struct {
	Chain   common.Chain
	AssetID string
	Address string
}