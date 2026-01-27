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
) ([]byte, error) {
	if len(s.providers) == 0 {
		return nil, fmt.Errorf("no providers available")
	}

	providers := s.providers

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
	var bestProvider string
	var lastErr error

	// Log all provider results for debugging
	for _, result := range results {
		if result.err != nil {
			logrus.WithFields(logrus.Fields{
				"provider": result.name,
				"error":    result.err.Error(),
			}).Debug("evm swap provider failed")
			lastErr = result.err
			continue
		}

		logrus.WithFields(logrus.Fields{
			"provider":  result.name,
			"amountOut": result.amountOut.String(),
		}).Debug("evm swap provider succeeded")

		if result.amountOut != nil && result.amountOut.Cmp(bestAmountOut) > 0 {
			bestAmountOut = result.amountOut
			bestTx = result.tx
			bestProvider = result.name
		}
	}

	if bestTx != nil {
		logrus.WithFields(logrus.Fields{
			"selectedProvider": bestProvider,
			"bestAmountOut":    bestAmountOut.String(),
		}).Info("selected best swap provider")
		return bestTx, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all providers failed, last error: %w", lastErr)
	}
	return nil, fmt.Errorf("no valid transactions found")
}
