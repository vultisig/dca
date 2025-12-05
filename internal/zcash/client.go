package zcash

import (
	"bytes"
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
		Code           int    `json:"code"`
		Source         string `json:"source"`
		Limit          string `json:"limit"`
		Offset         string `json:"offset"`
		Results        int    `json:"results"`
		State          int    `json:"state"`
		MarketPriceUsd int    `json:"market_price_usd"`
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
		return nil, fmt.Errorf("failed to get raw tx: %w", err)
	}

	data, ok := r.Data[txHash]
	if !ok {
		return nil, fmt.Errorf("failed to get tx from response, hash=%s", txHash)
	}

	txBytes, err := hex.DecodeString(data.RawTx)
	if err != nil {
		return nil, fmt.Errorf("failed to decode raw tx hex: %w", err)
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
		return "", fmt.Errorf("failed to push tx: %w", err)
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
		return 0, fmt.Errorf("failed to fetch address info: %w", err)
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

// SerializeUnsignedTx creates raw unsigned transaction bytes
// Uses Zcash v4 (Sapling) format for compatibility with recipes engine
func SerializeUnsignedTx(inputs []TxInput, outputs []*TxOutput) ([]byte, error) {
	var buf bytes.Buffer

	// Zcash v4 transaction format (Sapling)
	// Header: 4 bytes version + 4 bytes version group ID

	// Version (4 bytes, little-endian) - version 4 with overwintered flag
	version := uint32(0x80000004) // Version 4 with overwintered flag
	buf.WriteByte(byte(version))
	buf.WriteByte(byte(version >> 8))
	buf.WriteByte(byte(version >> 16))
	buf.WriteByte(byte(version >> 24))

	// Version group ID (4 bytes, little-endian) - Sapling
	versionGroupID := uint32(0x892F2085) // Sapling version group ID
	buf.WriteByte(byte(versionGroupID))
	buf.WriteByte(byte(versionGroupID >> 8))
	buf.WriteByte(byte(versionGroupID >> 16))
	buf.WriteByte(byte(versionGroupID >> 24))

	// Transparent inputs count (compactSize)
	writeCompactSize(&buf, uint64(len(inputs)))

	// Transparent inputs
	for _, input := range inputs {
		// Previous output hash (32 bytes)
		txHashBytes, err := hex.DecodeString(input.TxHash)
		if err != nil {
			return nil, fmt.Errorf("invalid tx hash: %w", err)
		}
		// Reverse for little-endian
		for i := len(txHashBytes) - 1; i >= 0; i-- {
			buf.WriteByte(txHashBytes[i])
		}

		// Previous output index (4 bytes, little-endian)
		buf.WriteByte(byte(input.Index))
		buf.WriteByte(byte(input.Index >> 8))
		buf.WriteByte(byte(input.Index >> 16))
		buf.WriteByte(byte(input.Index >> 24))

		// Script length (compactSize) - empty for unsigned
		buf.WriteByte(0x00)

		// Sequence (4 bytes, little-endian) - 0xffffffff
		buf.WriteByte(0xff)
		buf.WriteByte(0xff)
		buf.WriteByte(0xff)
		buf.WriteByte(0xff)
	}

	// Transparent outputs count (compactSize)
	writeCompactSize(&buf, uint64(len(outputs)))

	// Transparent outputs
	for _, output := range outputs {
		// Value (8 bytes, little-endian)
		value := uint64(output.Value)
		buf.WriteByte(byte(value))
		buf.WriteByte(byte(value >> 8))
		buf.WriteByte(byte(value >> 16))
		buf.WriteByte(byte(value >> 24))
		buf.WriteByte(byte(value >> 32))
		buf.WriteByte(byte(value >> 40))
		buf.WriteByte(byte(value >> 48))
		buf.WriteByte(byte(value >> 56))

		// Script length (compactSize)
		writeCompactSize(&buf, uint64(len(output.Script)))

		// Script
		buf.Write(output.Script)
	}

	// Lock time (4 bytes, little-endian)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)

	// Expiry height (4 bytes, little-endian) - 0 for no expiry
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)

	// Value balance (8 bytes, little-endian) - 0 for transparent-only
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)

	// Shielded spends count (compactSize) - 0 for transparent-only
	buf.WriteByte(0x00)

	// Shielded outputs count (compactSize) - 0 for transparent-only
	buf.WriteByte(0x00)

	// JoinSplits count (compactSize) - 0 for transparent-only (Sapling v4)
	buf.WriteByte(0x00)

	return buf.Bytes(), nil
}

// writeCompactSize writes a variable-length integer
func writeCompactSize(buf *bytes.Buffer, n uint64) {
	if n < 253 {
		buf.WriteByte(byte(n))
	} else if n <= 0xFFFF {
		buf.WriteByte(253)
		buf.WriteByte(byte(n))
		buf.WriteByte(byte(n >> 8))
	} else if n <= 0xFFFFFFFF {
		buf.WriteByte(254)
		buf.WriteByte(byte(n))
		buf.WriteByte(byte(n >> 8))
		buf.WriteByte(byte(n >> 16))
		buf.WriteByte(byte(n >> 24))
	} else {
		buf.WriteByte(255)
		buf.WriteByte(byte(n))
		buf.WriteByte(byte(n >> 8))
		buf.WriteByte(byte(n >> 16))
		buf.WriteByte(byte(n >> 24))
		buf.WriteByte(byte(n >> 32))
		buf.WriteByte(byte(n >> 40))
		buf.WriteByte(byte(n >> 48))
		buf.WriteByte(byte(n >> 56))
	}
}

// TxInput represents a transaction input
type TxInput struct {
	TxHash   string
	Index    uint32
	Value    uint64
	Script   []byte
	Sequence uint32
}
