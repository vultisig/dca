package xrp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// AccountInfoProvider interface defines methods for fetching XRP account and network data
type AccountInfoProvider interface {
	GetAccountInfo(ctx context.Context, address string) (sequence uint32, err error)
	GetCurrentLedger(ctx context.Context) (ledgerIndex uint32, err error)
	GetBaseFee(ctx context.Context) (feeDrops uint64, err error)
}

// Client implements AccountInfoProvider using XRPL JSON-RPC
type Client struct {
	rpcURL     string
	httpClient *http.Client
}

// NewClient creates a new XRP client with the given RPC URL
func NewClient(rpcURL string) *Client {
	return &Client{
		rpcURL: rpcURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// XRPL JSON-RPC request/response structures
type xrplRequest struct {
	Method  string        `json:"method"`
	Params  []xrplParam   `json:"params"`
	ID      int           `json:"id"`
	JSONRPC string        `json:"jsonrpc"`
}

type xrplParam struct {
	Account      string `json:"account,omitempty"`
	LedgerIndex  string `json:"ledger_index,omitempty"`
	Strict       bool   `json:"strict,omitempty"`
	LedgerHash   string `json:"ledger_hash,omitempty"`
	Transactions bool   `json:"transactions,omitempty"`
	Queue        bool   `json:"queue,omitempty"`
}

type xrplResponse struct {
	Result xrplResult `json:"result"`
	Status string     `json:"status,omitempty"`
	Error  string     `json:"error,omitempty"`
}

type xrplResult struct {
	Status         string      `json:"status,omitempty"`
	AccountData    accountData `json:"account_data,omitempty"`
	LedgerIndex    interface{} `json:"ledger_index,omitempty"`
	Info           serverInfo  `json:"info,omitempty"`
	Validated      bool        `json:"validated,omitempty"`
	Error          string      `json:"error,omitempty"`
	ErrorMessage   string      `json:"error_message,omitempty"`
}

type accountData struct {
	Account  string      `json:"Account"`
	Sequence interface{} `json:"Sequence"`
}

type serverInfo struct {
	ValidatedLedger validatedLedger `json:"validated_ledger,omitempty"`
	BaseFee         interface{}     `json:"base_fee,omitempty"`
	BaseFeeXRP      interface{}     `json:"base_fee_xrp,omitempty"`
}

type validatedLedger struct {
	Seq interface{} `json:"seq,omitempty"`
}

// makeRequest performs an XRPL JSON-RPC request
func (c *Client) makeRequest(ctx context.Context, command string, params map[string]interface{}) (*xrplResponse, error) {
	param := xrplParam{}
	
	// Add parameters based on input
	for key, value := range params {
		switch key {
		case "account":
			if s, ok := value.(string); ok {
				param.Account = s
			}
		case "ledger_index":
			if s, ok := value.(string); ok {
				param.LedgerIndex = s
			}
		case "strict":
			if b, ok := value.(bool); ok {
				param.Strict = b
			}
		case "queue":
			if b, ok := value.(bool); ok {
				param.Queue = b
			}
		}
	}

	reqBody := xrplRequest{
		Method:  command,
		Params:  []xrplParam{param},
		ID:      1,
		JSONRPC: "2.0",
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("xrp: failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.rpcURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("xrp: failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("xrp: failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("xrp: unexpected status code: %d", resp.StatusCode)
	}

	var xrplResp xrplResponse
	if err := json.NewDecoder(resp.Body).Decode(&xrplResp); err != nil {
		return nil, fmt.Errorf("xrp: failed to decode response: %w", err)
	}

	if xrplResp.Result.Error != "" {
		return nil, fmt.Errorf("xrp: XRPL error: %s - %s", xrplResp.Result.Error, xrplResp.Result.ErrorMessage)
	}

	return &xrplResp, nil
}

// GetAccountInfo fetches account sequence number from XRPL
func (c *Client) GetAccountInfo(ctx context.Context, address string) (uint32, error) {
	resp, err := c.makeRequest(ctx, "account_info", map[string]interface{}{
		"account":      address,
		"strict":       true,
		"ledger_index": "validated",
	})
	if err != nil {
		return 0, fmt.Errorf("xrp: failed to get account info: %w", err)
	}

	// Parse sequence number (can be string or number)
	var sequence uint32
	switch v := resp.Result.AccountData.Sequence.(type) {
	case float64:
		sequence = uint32(v)
	case string:
		seq, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("xrp: failed to parse sequence: %w", err)
		}
		sequence = uint32(seq)
	default:
		return 0, fmt.Errorf("xrp: unexpected sequence type: %T", v)
	}

	return sequence, nil
}

// GetCurrentLedger fetches current validated ledger index from XRPL
func (c *Client) GetCurrentLedger(ctx context.Context) (uint32, error) {
	resp, err := c.makeRequest(ctx, "ledger", map[string]interface{}{
		"ledger_index": "validated",
	})
	if err != nil {
		return 0, fmt.Errorf("xrp: failed to get current ledger: %w", err)
	}

	// Parse ledger index (can be string or number)  
	var ledgerIndex uint32
	switch v := resp.Result.LedgerIndex.(type) {
	case float64:
		ledgerIndex = uint32(v)
	case string:
		idx, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("xrp: failed to parse ledger index: %w", err)
		}
		ledgerIndex = uint32(idx)
	default:
		return 0, fmt.Errorf("xrp: unexpected ledger index type: %T", v)
	}

	return ledgerIndex, nil
}

// GetBaseFee fetches current base fee from XRPL network
func (c *Client) GetBaseFee(ctx context.Context) (uint64, error) {
	resp, err := c.makeRequest(ctx, "server_info", map[string]interface{}{})
	if err != nil {
		return 0, fmt.Errorf("xrp: failed to get base fee: %w", err)
	}

	// Parse base fee (can be in different formats)
	var baseFee uint64 = 12 // Default XRP fee

	if resp.Result.Info.BaseFee != nil {
		switch v := resp.Result.Info.BaseFee.(type) {
		case float64:
			baseFee = uint64(v)
		case string:
			fee, err := strconv.ParseUint(v, 10, 64)
			if err == nil {
				baseFee = fee
			}
		}
	}

	// Ensure minimum fee for memo transactions (slightly higher than base)
	if baseFee < 12 {
		baseFee = 12
	}

	return baseFee, nil
}