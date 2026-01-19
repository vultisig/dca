package zcash

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/vultisig/verifier/plugin/libhttp"
)

// Client handles Zcash blockchain interactions via Blockchair API
type Client struct {
	url string
}

// NewClient creates a new Zcash client with the given Blockchair URL
func NewClient(url string) *Client {
	return &Client{
		url: url,
	}
}

// Utxo represents an unspent transaction output
type Utxo struct {
	BlockId         int    `json:"block_id"`
	TransactionHash string `json:"transaction_hash"`
	Index           uint32 `json:"index"`
	Value           uint64 `json:"value"`
}

// UnspentResponse wraps UTXO batch with potential error
type UnspentResponse struct {
	Utxos []Utxo
	Err   error
}

// addrInfoResponse matches Blockchair's address info response
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
		Code           int     `json:"code"`
		Source         string  `json:"source"`
		Limit          string  `json:"limit"`
		Offset         string  `json:"offset"`
		Results        int     `json:"results"`
		State          int     `json:"state"`
		MarketPriceUsd float64 `json:"market_price_usd"`
	} `json:"context"`
}

// PushResponse matches Blockchair's transaction push response
type PushResponse struct {
	Data struct {
		TransactionHash string `json:"transaction_hash"`
	} `json:"data"`
}

// RawTxResponse matches Blockchair's raw transaction response
type RawTxResponse struct {
	Data map[string]struct {
		RawTx string `json:"raw_transaction"`
	} `json:"data"`
}

// GetUnspent returns a channel of UTXOs for the given address
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
				c.url+"/zcash/dashboards/address/"+address,
				nil,
				nil,
				map[string]string{
					"offset": fmt.Sprintf("%d", offset),
					"limit":  fmt.Sprintf("0,%d", limit),
				},
			)
			if err != nil {
				ch <- UnspentResponse{
					Err: fmt.Errorf("zcash: failed to fetch address info: %w", err),
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

// GetRawTransaction fetches a raw transaction by its hash
func (c *Client) GetRawTransaction(txHash string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	r, err := libhttp.Call[RawTxResponse](
		ctx,
		http.MethodGet,
		c.url+"/zcash/raw/transaction/"+txHash,
		map[string]string{
			"Content-Type": "application/json",
		},
		map[string]string{},
		map[string]string{},
	)
	if err != nil {
		return nil, fmt.Errorf("zcash: failed to get raw tx: %w", err)
	}

	data, ok := r.Data[txHash]
	if !ok {
		return nil, fmt.Errorf("zcash: tx not found in response, hash=%s", txHash)
	}

	txBytes, err := hex.DecodeString(data.RawTx)
	if err != nil {
		return nil, fmt.Errorf("zcash: failed to decode raw tx hex: %w", err)
	}

	return txBytes, nil
}

// BroadcastTransaction broadcasts a signed transaction to the network
func (c *Client) BroadcastTransaction(signedTx []byte) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := libhttp.Call[PushResponse](
		ctx,
		http.MethodPost,
		c.url+"/zcash/push/transaction",
		map[string]string{
			"Content-Type": "application/json",
		},
		map[string]string{
			"data": hex.EncodeToString(signedTx),
		},
		map[string]string{},
	)
	if err != nil {
		return "", fmt.Errorf("zcash: failed to push tx: %w", err)
	}

	return res.Data.TransactionHash, nil
}

// GetAddressBalance returns the balance of an address in zatoshis
func (c *Client) GetAddressBalance(ctx context.Context, address string) (int64, error) {
	batch, err := libhttp.Call[addrInfoResponse](
		ctx,
		http.MethodGet,
		c.url+"/zcash/dashboards/address/"+address,
		nil,
		nil,
		nil,
	)
	if err != nil {
		return 0, fmt.Errorf("zcash: failed to fetch address info: %w", err)
	}

	val, ok := batch.Data[address]
	if !ok {
		return 0, nil
	}

	return val.Address.Balance, nil
}

// UtxoProvider interface for transaction building
type UtxoProvider interface {
	GetUnspent(ctx context.Context, address string) <-chan UnspentResponse
	GetRawTransaction(txHash string) ([]byte, error)
}

// Ensure Client implements UtxoProvider
var _ UtxoProvider = (*Client)(nil)

// TxBroadcaster interface for broadcasting transactions
type TxBroadcaster interface {
	BroadcastTransaction(signedTx []byte) (string, error)
}

// Ensure Client implements TxBroadcaster
var _ TxBroadcaster = (*Client)(nil)
