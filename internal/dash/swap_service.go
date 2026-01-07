package dash

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/wire"
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
) (uint64, []*wire.TxOut, int, error) {
	if len(s.providers) == 0 {
		return 0, nil, 0, fmt.Errorf("dash: no swap providers available")
	}

	// For now, just use the first provider
	provider := s.providers[0]

	toAmount, outputs, err := provider.MakeOutputs(ctx, from, to)
	if err != nil {
		return 0, nil, 0, fmt.Errorf("dash: provider failed: %w", err)
	}

	return toAmount, outputs, provider.ChangeOutputIndex(), nil
}

