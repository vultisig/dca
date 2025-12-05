package zcash

import (
	"github.com/vultisig/vultisig-go/common"
)

type From struct {
	PubKey  []byte // 33-byte compressed public key
	Address string // t1... transparent address
	Amount  uint64 // Amount in zatoshis (1 ZEC = 100,000,000 zatoshis)
}

// To destination could be not ZEC chain
type To struct {
	Chain   common.Chain
	AssetID string
	Address string
}
