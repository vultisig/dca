package solana

import (
	"context"
	"fmt"
	"math/big"

	"github.com/gagliardetto/solana-go/rpc"
	"golang.org/x/sync/errgroup"
)

type swapService struct {
	rpcClient *rpc.Client
	providers []Provider
}

func newSwapService(rpcClient *rpc.Client, providers []Provider) *swapService {
	return &swapService{
		rpcClient: rpcClient,
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
