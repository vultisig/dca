package btc

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/wire"
	"golang.org/x/sync/errgroup"
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
) (int, uint64, []*wire.TxOut, error) {
	if len(s.providers) == 0 {
		return 0, 0, nil, fmt.Errorf("no providers available")
	}

	type providerResult struct {
		changeOutputIndex int
		amountOut         uint64
		outputs           []*wire.TxOut
		err               error
	}
	results := make([]providerResult, len(s.providers))

	g, ctx := errgroup.WithContext(ctx)

	for _i, _provider := range s.providers {
		i, provider := _i, _provider
		g.Go(func() error {
			amountOut, outputs, err := provider.MakeOutputs(ctx, from, to)

			results[i] = providerResult{
				changeOutputIndex: provider.ChangeOutputIndex(),
				amountOut:         amountOut,
				outputs:           outputs,
				err:               err,
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return 0, 0, nil, fmt.Errorf("errgroup failed: %w", err)
	}

	var changeOutputIndex int
	var bestTx []*wire.TxOut
	var bestAmountOut uint64
	var lastErr error

	for _, result := range results {
		if result.err != nil {
			lastErr = result.err
			continue
		}

		if result.amountOut > bestAmountOut {
			changeOutputIndex = result.changeOutputIndex
			bestAmountOut = result.amountOut
			bestTx = result.outputs
		}
	}

	if bestTx == nil {
		if lastErr != nil {
			return 0, 0, nil, fmt.Errorf("all providers failed, last error: %w", lastErr)
		}
		return 0, 0, nil, fmt.Errorf("no valid transactions found")
	}

	return changeOutputIndex, bestAmountOut, bestTx, nil
}
