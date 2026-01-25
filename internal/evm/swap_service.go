package evm

import (
	"context"
	"fmt"
	"math/big"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
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
	routePreference string,
) ([]byte, error) {
	if len(s.providers) == 0 {
		return nil, fmt.Errorf("no providers available")
	}

	providers := s.filterProviders(routePreference)
	if len(providers) == 0 {
		return nil, fmt.Errorf("no providers available for route preference: %s", routePreference)
	}

	type providerResult struct {
		amountOut *big.Int
		tx        []byte
		err       error
		name      string
	}
	results := make([]providerResult, len(providers))

	g, ctx := errgroup.WithContext(ctx)

	for _i, _provider := range providers {
		i, provider := _i, _provider
		g.Go(func() error {
			amountOut, tx, err := provider.MakeTx(ctx, from, to)

			results[i] = providerResult{
				amountOut: amountOut,
				tx:        tx,
				err:       err,
				name:      provider.Name(),
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("errgroup failed: %w", err)
	}

	var bestTx []byte
	var bestAmountOut = big.NewInt(0)
	var lastErr error

	for _, result := range results {
		if result.err != nil {
			logrus.WithFields(logrus.Fields{
				"provider": result.name,
				"error":    result.err.Error(),
			}).Debug("evm swap provider failed")
			lastErr = result.err
			continue
		}

		if result.amountOut != nil && result.amountOut.Cmp(bestAmountOut) > 0 {
			bestAmountOut = result.amountOut
			bestTx = result.tx
		}
	}

	if bestTx != nil {
		return bestTx, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all providers failed, last error: %w", lastErr)
	}
	return nil, fmt.Errorf("no valid transactions found")
}

func (s *swapService) filterProviders(routePreference string) []Provider {
	if routePreference == "" || routePreference == "auto" {
		return s.providers
	}

	var filtered []Provider
	for _, p := range s.providers {
		if p.Name() == routePreference {
			filtered = append(filtered, p)
		}
	}

	if len(filtered) == 0 {
		logrus.WithField("routePreference", routePreference).Warn("no providers match route preference, falling back to all providers")
		return s.providers
	}

	return filtered
}
