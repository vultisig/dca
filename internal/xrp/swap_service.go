package xrp

import (
	"context"
	"fmt"
)

type SwapService struct {
	providers []SwapProvider
}

func NewSwapService(providers []SwapProvider) *SwapService {
	return &SwapService{
		providers: providers,
	}
}

func (s *SwapService) FindBestAmountOut(
	ctx context.Context,
	from From,
	to To,
) ([]byte, uint64, error) {
	if len(s.providers) == 0 {
		return nil, 0, fmt.Errorf("no providers available")
	}

	// For now, just use the first provider
	// TODO: Implement best route finding logic when we have multiple providers
	provider := s.providers[0]

	txData, toAmount, err := provider.MakeTransaction(ctx, from, to)
	if err != nil {
		return nil, 0, fmt.Errorf("provider failed: %w", err)
	}

	return txData, toAmount, nil
}
