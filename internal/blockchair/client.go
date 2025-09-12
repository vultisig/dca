package blockchair

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
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

type PushResponse struct {
	Data struct {
		TransactionHash string `json:"transaction_hash"`
	} `json:"data"`
}

func (c *Client) SendRawTransaction(tx *wire.MsgTx, _ bool) (*chainhash.Hash, error) {
	var b bytes.Buffer
	err := tx.Serialize(&b)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize tx: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := libhttp.Call[PushResponse](
		ctx,
		http.MethodPost,
		c.url+"/bitcoin/push/transaction",
		map[string]string{
			"Content-Type": "application/json",
		},
		map[string]string{
			"data": hex.EncodeToString(b.Bytes()),
		},
		map[string]string{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to push tx: %w", err)
	}

	hash, err := chainhash.NewHashFromStr(res.Data.TransactionHash)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tx hash: %w", err)
	}
	return hash, nil
}

type Utxo struct {
	BlockId         int    `json:"block_id"`
	TransactionHash string `json:"transaction_hash"`
	Index           uint32 `json:"index"`
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
				c.url+"/bitcoin/dashboards/address/"+address,
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
