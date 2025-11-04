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

// Client implements AccountInfoProvider using THORChain Tendermint JSON-RPC
type Client struct {
	rpcURL     string
	httpClient *http.Client
}

// NewClient creates a new THORChain client with the given RPC URL
func NewClient(rpcURL string) *Client {
	return &Client{
		rpcURL: rpcURL,
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

	req, err := http.NewRequestWithContext(ctx, "POST", c.rpcURL, bytes.NewBuffer(jsonData))
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
	// Query account info using abci_query
	path := fmt.Sprintf("account/%s", address)
	params := []interface{}{path, "", "0", false}

	resp, err := c.makeRequest(ctx, "abci_query", params)
	if err != nil {
		return 0, fmt.Errorf("thorchain: failed to query account info: %w", err)
	}

	var queryResp abciQueryResponse
	if err := json.Unmarshal(resp.Result, &queryResp); err != nil {
		return 0, fmt.Errorf("thorchain: failed to unmarshal account query response: %w", err)
	}

	if queryResp.Response.Code != 0 {
		return 0, fmt.Errorf("thorchain: account query failed: %s", queryResp.Response.Log)
	}

	// TODO: Parse account data from queryResp.Response.Value (base64 encoded protobuf)
	// For now, return a default sequence number
	// In a real implementation, you would:
	// 1. Base64 decode queryResp.Response.Value
	// 2. Protobuf decode the account data using Cosmos SDK types
	// 3. Extract the sequence number from the account
	return 0, nil
}

// GetLatestBlock fetches current block height from THORChain
func (c *Client) GetLatestBlock(ctx context.Context) (uint64, error) {
	resp, err := c.makeRequest(ctx, "block", []interface{}{})
	if err != nil {
		return 0, fmt.Errorf("thorchain: failed to get latest block: %w", err)
	}

	var blockResp blockResponse
	if err := json.Unmarshal(resp.Result, &blockResp); err != nil {
		return 0, fmt.Errorf("thorchain: failed to unmarshal block response: %w", err)
	}

	heightStr := blockResp.Block.Header.Height
	height, err := strconv.ParseUint(heightStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("thorchain: failed to parse block height: %w", err)
	}

	return height, nil
}

// GetBaseFee fetches current base fee from THORChain network
func (c *Client) GetBaseFee(ctx context.Context) (uint64, error) {
	// THORChain uses a fixed gas price model
	// Default gas price is typically 0.02 RUNE per gas unit
	// For now, return a reasonable default
	return 200000000, nil // 2 RUNE in base units (1e8)
}