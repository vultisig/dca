package thorchain_native

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// AccountInfoProvider interface defines methods for fetching THORChain account and network data
type AccountInfoProvider interface {
	GetAccountInfo(ctx context.Context, address string) (sequence uint64, err error)
	GetLatestBlock(ctx context.Context) (height uint64, err error)
	GetBaseFee(ctx context.Context) (fee uint64, err error)
}

// Client implements AccountInfoProvider using THORChain APIs
type Client struct {
	cosmosRpcURL    string // Tendermint RPC endpoint for block queries
	thorchainApiURL string // THORChain API endpoint for account and network queries
	httpClient      *http.Client
}

// NewClient creates a new THORChain client with both Cosmos RPC and THORChain API URLs
func NewClient(cosmosRpcURL, thorchainApiURL string) *Client {
	return &Client{
		cosmosRpcURL:    cosmosRpcURL,
		thorchainApiURL: thorchainApiURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Tendermint JSON-RPC request/response structures
type tendermintRequest struct {
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
	JSONRPC string        `json:"jsonrpc"`
}

type tendermintResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error,omitempty"`
	ID     int             `json:"id"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

type abciQueryResponse struct {
	Response abciResponse `json:"response"`
}

type abciResponse struct {
	Code  int    `json:"code"`
	Log   string `json:"log"`
	Info  string `json:"info"`
	Index string `json:"index"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

type blockResponse struct {
	Block blockData `json:"block"`
}

type blockData struct {
	Header blockHeader `json:"header"`
}

type blockHeader struct {
	Height string `json:"height"`
}

// makeRequest performs a Tendermint JSON-RPC request
func (c *Client) makeRequest(ctx context.Context, method string, params []interface{}) (*tendermintResponse, error) {
	reqBody := tendermintRequest{
		Method:  method,
		Params:  params,
		ID:      1,
		JSONRPC: "2.0",
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("thorchain: failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.cosmosRpcURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("thorchain: failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("thorchain: failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("thorchain: unexpected status code: %d", resp.StatusCode)
	}

	var tmResp tendermintResponse
	if err := json.NewDecoder(resp.Body).Decode(&tmResp); err != nil {
		return nil, fmt.Errorf("thorchain: failed to decode response: %w", err)
	}

	if tmResp.Error != nil {
		return nil, fmt.Errorf("thorchain: RPC error: %s", tmResp.Error.Message)
	}

	return &tmResp, nil
}

// GetAccountInfo fetches account sequence number from THORChain
func (c *Client) GetAccountInfo(ctx context.Context, address string) (uint64, error) {
	// Use Cosmos REST API endpoint for account info
	// THORChain follows standard Cosmos SDK patterns
	url := fmt.Sprintf("%s/cosmos/auth/v1beta1/accounts/%s", c.thorchainApiURL, address)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, fmt.Errorf("thorchain: failed to create account request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("thorchain: failed to query account info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("thorchain: unexpected status code: %d", resp.StatusCode)
	}

	var accountResp struct {
		Account struct {
			Sequence string `json:"sequence"`
		} `json:"account"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&accountResp); err != nil {
		return 0, fmt.Errorf("thorchain: failed to decode account response: %w", err)
	}

	sequence, err := strconv.ParseUint(accountResp.Account.Sequence, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("thorchain: failed to parse sequence: %w", err)
	}

	return sequence, nil
}

// GetLatestBlock fetches current block height from THORChain
func (c *Client) GetLatestBlock(ctx context.Context) (uint64, error) {
	// Use Tendermint RPC status endpoint to get latest block height
	url := fmt.Sprintf("%s/status", c.cosmosRpcURL)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, fmt.Errorf("thorchain: failed to create block request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("thorchain: failed to get latest block: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("thorchain: unexpected status code: %d", resp.StatusCode)
	}

	var statusResp struct {
		Result struct {
			SyncInfo struct {
				LatestBlockHeight   string `json:"latest_block_height"`
				EarliestBlockHeight string `json:"earliest_block_height"`
			} `json:"sync_info"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&statusResp); err != nil {
		return 0, fmt.Errorf("thorchain: failed to decode status response: %w", err)
	}

	// Parse block height from string
	height, err := strconv.ParseUint(statusResp.Result.SyncInfo.LatestBlockHeight, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("thorchain: failed to parse block height: %w", err)
	}

	fmt.Printf("DEBUG THORCHAIN STATUS RESPONSE:\n")
	fmt.Printf("  Latest Block Height: %s (%d)\n", statusResp.Result.SyncInfo.LatestBlockHeight, height)

	return height, nil
}

// GetBaseFee fetches current base fee from THORChain network
func (c *Client) GetBaseFee(ctx context.Context) (uint64, error) {
	// THORChain uses a fixed gas price model
	// Default gas price is typically 0.02 RUNE per gas unit
	// For now, return a reasonable default
	return 200000000, nil // 2 RUNE in base units (1e8)
}