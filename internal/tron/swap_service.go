package tron

import (
	"context"
	"fmt"
)

// SwapService handles finding the best swap route across providers
type SwapService struct {
	providers []SwapProvider
}

// NewSwapService creates a new SwapService with the given providers
func NewSwapService(providers []SwapProvider) *SwapService {
	return &SwapService{
		providers: providers,
	}
}

// FindBestAmountOut finds the best swap route across all providers
func (s *SwapService) FindBestAmountOut(
	ctx context.Context,
	from From,
	to To,
) ([]byte, uint64, error) {
	if len(s.providers) == 0 {
		return nil, 0, fmt.Errorf("tron: no swap providers available")
	}

	// For now, just use the first provider
	// TODO: Implement best route finding logic when we have multiple providers
	provider := s.providers[0]

	txData, toAmount, err := provider.MakeTransaction(ctx, from, to)
	if err != nil {
		return nil, 0, fmt.Errorf("tron: provider failed: %w", err)
	}

	return txData, toAmount, nil
}

