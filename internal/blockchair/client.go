package blockchair

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/vultisig/verifier/plugin/libhttp"
)

type Client struct {
	url string
}

func NewClient(url string) *Client {
	return &Client{
		url: url,
	}
}

type Utxo struct {
	BlockId         int    `json:"block_id"`
	TransactionHash string `json:"transaction_hash"`
	Index           int    `json:"index"`
	Value           uint64 `json:"value"`
}

type UnspentResponse struct {
	Utxos []Utxo
	Err   error
}

func (c *Client) GetUnspent(ctx context.Context, address string) <-chan UnspentResponse {
	ch := make(chan UnspentResponse)

	go func() {
		defer close(ch)

		offset := 0
		const limit = 50
		for ctx.Err() == nil {
			batch, err := libhttp.Call[addrInfoResponse](
				ctx,
				http.MethodGet,
				c.url+"/blockchair/bitcoin/dashboards/address/"+address,
				nil,
				nil,
				map[string]string{
					"offset": fmt.Sprintf("%d", offset),
					"limit":  fmt.Sprintf("0,%d", limit),
				},
			)
			if err != nil {
				ch <- UnspentResponse{
					Err: fmt.Errorf("failed to fetch address info: %w", err),
				}
				return
			}

			val, ok := batch.Data[address]
			if !ok {
				return
			}

			ch <- UnspentResponse{
				Utxos: val.Utxo,
			}
			if len(val.Utxo) < limit {
				return
			}

			offset += limit
		}
	}()

	return ch
}

func (c *Client) pickUntil(
	ct context.Context,
	address string,
	minValueTotal uint64,
	maxUtxosCount int,
) (bool, []Utxo, error) {
	ctx, cancel := context.WithCancel(ct)
	defer cancel()

	var valueTotal uint64
	var utxos []Utxo
	ch := c.GetUnspent(ctx, address)
	for unspent := range ch {
		if unspent.Err != nil {
			return false, nil, fmt.Errorf("failed to get unspent: %w", unspent.Err)
		}

		for _, utxo := range unspent.Utxos {
			if valueTotal >= minValueTotal && len(utxos) <= maxUtxosCount {
				cancel()
				_ = <-ch // release blocking ch writer of the next batch, if any
				return true, utxos, nil
			}

			utxos = append(utxos, utxo)
			valueTotal += utxo.Value
		}
	}

	return false, nil, nil
}

var ErrUnsufficientBalance = errors.New("unsufficient balance")

func (c *Client) PickUnspent(
	ctx context.Context,
	address string,
	minValueTotal uint64,
	maxUtxosCount int,
) ([]Utxo, error) {
	// fast path
	ok, pickUtxos, err := c.pickUntil(ctx, address, minValueTotal, maxUtxosCount)
	if err != nil {
		return nil, fmt.Errorf("failed to pick utxos: %w", err)
	}
	if ok {
		return pickUtxos, nil
	}

	// slow path: get all unspent on address, sort desc by value, and take maxUtxosCount of minValueTotal
	ch := c.GetUnspent(ctx, address)
	var allUtxos []Utxo
	for unspent := range ch {
		if unspent.Err != nil {
			return nil, fmt.Errorf("failed to get unspent: %w", unspent.Err)
		}
		allUtxos = append(allUtxos, unspent.Utxos...)
	}

	slices.SortStableFunc(allUtxos, func(a, b Utxo) int {
		return cmp.Compare(a.Value, b.Value)
	})

	var valueTotal uint64
	var utxos []Utxo
	for _, utxo := range allUtxos {
		if valueTotal >= minValueTotal && len(utxos) <= maxUtxosCount {
			return utxos, nil
		}

		utxos = append(utxos, utxo)
		valueTotal += utxo.Value
	}

	return nil, fmt.Errorf(
		"failed to pick utxos address=%s,minValueTotal=%d,maxUtxosCount=%d: %w",
		address,
		minValueTotal,
		maxUtxosCount,
		ErrUnsufficientBalance,
	)
}

type addrInfoResponse struct {
	Data map[string]struct {
		Address struct {
			Type               string      `json:"type"`
			ScriptHex          string      `json:"script_hex"`
			Balance            int64       `json:"balance"`
			BalanceUsd         float64     `json:"balance_usd"`
			Received           int64       `json:"received"`
			ReceivedUsd        float64     `json:"received_usd"`
			Spent              int64       `json:"spent"`
			SpentUsd           float64     `json:"spent_usd"`
			OutputCount        int         `json:"output_count"`
			UnspentOutputCount int         `json:"unspent_output_count"`
			FirstSeenReceiving string      `json:"first_seen_receiving"`
			LastSeenReceiving  string      `json:"last_seen_receiving"`
			FirstSeenSpending  string      `json:"first_seen_spending"`
			LastSeenSpending   string      `json:"last_seen_spending"`
			ScripthashType     interface{} `json:"scripthash_type"`
			TransactionCount   interface{} `json:"transaction_count"`
		} `json:"address"`
		Transactions []string `json:"transactions"`
		Utxo         []Utxo   `json:"utxo"`
	} `json:"data"`
	Context struct {
		Code           int    `json:"code"`
		Source         string `json:"source"`
		Limit          string `json:"limit"`
		Offset         string `json:"offset"`
		Results        int    `json:"results"`
		State          int    `json:"state"`
		MarketPriceUsd int    `json:"market_price_usd"`
		Cache          struct {
			Live     bool    `json:"live"`
			Duration int     `json:"duration"`
			Since    string  `json:"since"`
			Until    string  `json:"until"`
			Time     float64 `json:"time"`
		} `json:"cache"`
		Api struct {
			Version         string `json:"version"`
			LastMajorUpdate string `json:"last_major_update"`
			NextMajorUpdate string `json:"next_major_update"`
			Documentation   string `json:"documentation"`
			Notice          string `json:"notice"`
		} `json:"api"`
		Servers     string  `json:"servers"`
		Time        float64 `json:"time"`
		RenderTime  float64 `json:"render_time"`
		FullTime    float64 `json:"full_time"`
		RequestCost int     `json:"request_cost"`
	} `json:"context"`
}
