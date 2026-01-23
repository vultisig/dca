package evm

import (
	"context"
	"fmt"
)

type swapService struct {
	providers []Provider
}

func newSwapService(providers []Provider) *swapService {
	return &swapService{
		providers: providers,
	}
}

func (s *swapService) FindBestAmountOut(
	ctx context.Context,
	from From,
	to To,
) ([]byte, error) {
	if len(s.providers) == 0 {
		return nil, fmt.Errorf("no providers available")
	}

	var lastErr error
	for _, provider := range s.providers {
		_, tx, err := provider.MakeTx(ctx, from, to)
		if err != nil {
			lastErr = err
			continue
		}
		return tx, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all providers failed, last error: %w", lastErr)
	}
	return nil, fmt.Errorf("no valid transactions found")
}
