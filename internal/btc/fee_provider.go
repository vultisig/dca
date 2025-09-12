package btc

import "context"

type feeProvider interface {
	SatsPerByte(ctx context.Context) (uint64, error)
}
