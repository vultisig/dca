package tron

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AccountInfoProvider interface defines methods for fetching TRON account and network data
type AccountInfoProvider interface {
	GetAccount(ctx context.Context, address string) (*AccountInfo, error)
	GetNowBlock(ctx context.Context) (*Block, error)
	CreateTransaction(ctx context.Context, req *TransferRequest) (*Transaction, error)
}

// AccountInfo represents TRON account information
type AccountInfo struct {
	Address string `json:"address"`
	Balance int64  `json:"balance"`
}

// Block represents a TRON block
type Block struct {
	BlockID     string       `json:"blockID"`
	BlockHeader *BlockHeader `json:"block_header"`
}

// BlockHeader represents a TRON block header
type BlockHeader struct {
	RawData *BlockRawData `json:"raw_data"`
	Number  int64         `json:"number,omitempty"`
}

// BlockRawData represents raw data in a block header
type BlockRawData struct {
	Number         int64  `json:"number"`
	TxTrieRoot     string `json:"txTrieRoot"`
	WitnessAddress string `json:"witness_address"`
	ParentHash     string `json:"parentHash"`
	Version        int    `json:"version"`
	Timestamp      int64  `json:"timestamp"`
}

// TransferRequest represents a TRX transfer request
type TransferRequest struct {
	OwnerAddress string `json:"owner_address"`
	ToAddress    string `json:"to_address"`
	Amount       int64  `json:"amount"`
	Visible      bool   `json:"visible"`
}

// Transaction represents a TRON transaction
type Transaction struct {
	TxID       string   `json:"txID"`
	RawData    *RawData `json:"raw_data,omitempty"`
	RawDataHex string   `json:"raw_data_hex"`
	Visible    bool     `json:"visible,omitempty"`
}

// RawData represents the raw data of a TRON transaction
type RawData struct {
	Contract      []Contract `json:"contract"`
	RefBlockBytes string     `json:"ref_block_bytes"`
	RefBlockHash  string     `json:"ref_block_hash"`
	Expiration    int64      `json:"expiration"`
	Timestamp     int64      `json:"timestamp"`
	FeeLimit      int64      `json:"fee_limit,omitempty"`
	Data          string     `json:"data,omitempty"`
}

// Contract represents a contract in a TRON transaction
type Contract struct {
	Parameter Parameter `json:"parameter"`
	Type      string    `json:"type"`
}

// Parameter represents the parameter of a contract
type Parameter struct {
	Value   Value  `json:"value"`
	TypeUrl string `json:"type_url"`
}

// Value represents the value of a contract parameter
type Value struct {
	Amount       int64  `json:"amount,omitempty"`
	OwnerAddress string `json:"owner_address"`
	ToAddress    string `json:"to_address,omitempty"`
}

// Client implements AccountInfoProvider using TronGrid/TRON JSON-RPC
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new TRON client with the given base URL
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetAccount fetches account information from TRON network
func (c *Client) GetAccount(ctx context.Context, address string) (*AccountInfo, error) {
	reqBody := map[string]interface{}{
		"address": address,
		"visible": true,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("tron: failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/wallet/getaccount", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("tron: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tron: failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("tron: unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var account AccountInfo
	if err := json.NewDecoder(resp.Body).Decode(&account); err != nil {
		return nil, fmt.Errorf("tron: failed to decode response: %w", err)
	}

	return &account, nil
}

// GetNowBlock fetches the current block from TRON network
func (c *Client) GetNowBlock(ctx context.Context) (*Block, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/wallet/getnowblock", nil)
	if err != nil {
		return nil, fmt.Errorf("tron: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tron: failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("tron: unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var block Block
	if err := json.NewDecoder(resp.Body).Decode(&block); err != nil {
		return nil, fmt.Errorf("tron: failed to decode response: %w", err)
	}

	return &block, nil
}

// CreateTransaction creates an unsigned TRX transfer transaction
func (c *Client) CreateTransaction(ctx context.Context, transferReq *TransferRequest) (*Transaction, error) {
	jsonData, err := json.Marshal(transferReq)
	if err != nil {
		return nil, fmt.Errorf("tron: failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/wallet/createtransaction", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("tron: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tron: failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("tron: unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var tx Transaction
	if err := json.NewDecoder(resp.Body).Decode(&tx); err != nil {
		return nil, fmt.Errorf("tron: failed to decode response: %w", err)
	}

	return &tx, nil
}

