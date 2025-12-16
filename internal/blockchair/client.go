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

// GetAllUnspent fetches all UTXOs for an address.
func (c *Client) GetAllUnspent(ctx context.Context, address string) ([]Utxo, error) {
	var allUtxos []Utxo
	offset := 0
	const limit = 50

	for {
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
			return nil, fmt.Errorf("failed to fetch address info: %w", err)
		}

		val, ok := batch.Data[address]
		if !ok {
			break
		}

		allUtxos = append(allUtxos, val.Utxo...)
		if len(val.Utxo) < limit {
			break
		}
		offset += limit
	}

	return allUtxos, nil
}

// GetRawTransaction returns raw transaction bytes, implementing the sdk/btc.PrevTxFetcher interface.
func (c *Client) GetRawTransaction(txHash string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	type dataItem struct {
		RawTx string `json:"raw_transaction"`
	}

	type res struct {
		Data map[string]dataItem `json:"data"`
	}

	r, err := libhttp.Call[res](
		ctx,
		http.MethodGet,
		c.url+"/bitcoin/raw/transaction/"+txHash,
		map[string]string{
			"Content-Type": "application/json",
		},
		map[string]string{},
		map[string]string{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get raw tx: %w", err)
	}

	data, ok := r.Data[txHash]
	if !ok {
		return nil, fmt.Errorf("failed to get tx from response, hash=%s", txHash)
	}

	return hex.DecodeString(data.RawTx)
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
