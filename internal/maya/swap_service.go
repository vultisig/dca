package maya

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
) ([]byte, []byte, uint64, error) {
	if len(s.providers) == 0 {
		return nil, nil, 0, fmt.Errorf("maya: no swap providers available")
	}

	// For now, just use the first provider
	// TODO: Implement best route finding logic when we have multiple providers
	provider := s.providers[0]

	txData, signBytes, toAmount, err := provider.MakeTransaction(ctx, from, to)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("maya: provider failed: %w", err)
	}

	return txData, signBytes, toAmount, nil
}

