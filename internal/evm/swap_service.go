package evm

import (
	"context"
	"fmt"
	"math/big"

	ecommon "github.com/ethereum/go-ethereum/common"
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

func (s *swapService) GetApprovalSpender(
	ctx context.Context,
	from From,
	to To,
) (ecommon.Address, error) {
	for _, provider := range s.providers {
		if ap, ok := provider.(ApprovalProvider); ok {
			return ap.GetApprovalSpender(ctx, from, to)
		}
	}
	return ecommon.Address{}, fmt.Errorf("no approval provider available")
}

func (s *swapService) FindBestAmountOut(
	ctx context.Context,
	from From,
	to To,
) ([]byte, error) {
	if len(s.providers) == 0 {
		return nil, fmt.Errorf("no providers available")
	}

	type providerResult struct {
		amountOut *big.Int
		tx        []byte
		err       error
	}
	results := make([]providerResult, len(s.providers))

	g, ctx := errgroup.WithContext(ctx)

	for _i, _provider := range s.providers {
		i, provider := _i, _provider
		g.Go(func() error {
			amountOut, tx, err := provider.MakeTx(ctx, from, to)

			results[i] = providerResult{
				amountOut: amountOut,
				tx:        tx,
				err:       err,
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
			lastErr = result.err
			continue
		}

		if result.amountOut.Cmp(bestAmountOut) > 0 {
			bestAmountOut = result.amountOut
			bestTx = result.tx
		}
	}

	if bestTx == nil {
		if lastErr != nil {
			return nil, fmt.Errorf("all providers failed, last error: %w", lastErr)
		}
		return nil, fmt.Errorf("no valid transactions found")
	}

	return bestTx, nil
}
