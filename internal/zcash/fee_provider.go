package zcash

import "context"

type feeProvider interface {
	ZatoshisPerByte(ctx context.Context) (uint64, error)
}
