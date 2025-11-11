package thorchain_native

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// AccountInfo represents complete account information from THORChain
type AccountInfo struct {
	AccountNumber uint64
	Sequence      uint64
}


// Client provides THORChain account and network data access
type Client struct {
	tendermintRpcURL string // Tendermint RPC endpoint for blockchain operations (rpc.ninerealms.com)
	thorchainApiURL  string // THORChain API endpoint for account queries (thornode.ninerealms.com)
	httpClient       *http.Client
}

// NewClient creates a new THORChain client with both RPC endpoints
func NewClient(tendermintRpcURL, thorchainApiURL string) *Client {
	return &Client{
		tendermintRpcURL: tendermintRpcURL,
		thorchainApiURL:  thorchainApiURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}


// GetAccountInfo fetches account information (number and sequence) from THORChain
func (c *Client) GetAccountInfo(ctx context.Context, address string) (AccountInfo, error) {
	// Use Cosmos REST API endpoint for account info
	// THORChain follows standard Cosmos SDK patterns
	url := fmt.Sprintf("%s/cosmos/auth/v1beta1/accounts/%s", c.thorchainApiURL, address)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return AccountInfo{}, fmt.Errorf("thorchain: failed to create account request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return AccountInfo{}, fmt.Errorf("thorchain: failed to query account info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return AccountInfo{}, fmt.Errorf("thorchain: unexpected status code: %d", resp.StatusCode)
	}

	var accountResp struct {
		Account struct {
			AccountNumber string `json:"account_number"`
			Sequence      string `json:"sequence"`
		} `json:"account"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&accountResp); err != nil {
		return AccountInfo{}, fmt.Errorf("thorchain: failed to decode account response: %w", err)
	}

	accountNumber, err := strconv.ParseUint(accountResp.Account.AccountNumber, 10, 64)
	if err != nil {
		return AccountInfo{}, fmt.Errorf("thorchain: failed to parse account number: %w", err)
	}

	sequence, err := strconv.ParseUint(accountResp.Account.Sequence, 10, 64)
	if err != nil {
		return AccountInfo{}, fmt.Errorf("thorchain: failed to parse sequence: %w", err)
	}

	return AccountInfo{
		AccountNumber: accountNumber,
		Sequence:      sequence,
	}, nil
}

// GetLatestBlock fetches current block height from THORChain
func (c *Client) GetLatestBlock(ctx context.Context) (uint64, error) {
	// Use Tendermint RPC endpoint to get latest block height
	url := fmt.Sprintf("%s/status", c.tendermintRpcURL)

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
				LatestBlockHeight string `json:"latest_block_height"`
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

	return height, nil
}

// GetBaseFee fetches current base fee from THORChain network
func (c *Client) GetBaseFee(ctx context.Context) (uint64, error) {
	// Query THORChain constants for current native transaction fee
	url := fmt.Sprintf("%s/thorchain/constants", c.thorchainApiURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, fmt.Errorf("thorchain: failed to create constants request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("thorchain: failed to query constants: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("thorchain: unexpected status code: %d", resp.StatusCode)
	}

	var constantsResp struct {
		NativeTransactionFee uint64 `json:"NativeTransactionFee"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&constantsResp); err != nil {
		return 0, fmt.Errorf("thorchain: failed to decode constants response: %w", err)
	}

	return constantsResp.NativeTransactionFee, nil
}
