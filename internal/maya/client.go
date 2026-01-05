package maya

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// AccountInfoProvider interface defines methods for fetching MayaChain account and network data
type AccountInfoProvider interface {
	GetAccount(ctx context.Context, address string) (*AccountInfo, error)
	GetLatestBlock(ctx context.Context) (*BlockInfo, error)
}

// AccountInfo represents MayaChain account information
type AccountInfo struct {
	Address       string `json:"address"`
	AccountNumber uint64 `json:"account_number"`
	Sequence      uint64 `json:"sequence"`
}

// BlockInfo represents MayaChain block information
type BlockInfo struct {
	Height int64 `json:"height"`
}

// Client implements AccountInfoProvider using MayaChain LCD API
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new MayaChain client with the given LCD URL
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// lcdAccountResponse represents the MayaChain LCD API response for account query
type lcdAccountResponse struct {
	Account struct {
		Type    string `json:"@type"`
		Address string `json:"address"`
		PubKey  struct {
			Type string `json:"@type"`
			Key  string `json:"key"`
		} `json:"pub_key"`
		AccountNumber string `json:"account_number"`
		Sequence      string `json:"sequence"`
	} `json:"account"`
}

// lcdBlockResponse represents the MayaChain LCD API response for block query
type lcdBlockResponse struct {
	Block struct {
		Header struct {
			Height string `json:"height"`
		} `json:"header"`
	} `json:"block"`
}

// GetAccount fetches account information from MayaChain
func (c *Client) GetAccount(ctx context.Context, address string) (*AccountInfo, error) {
	url := fmt.Sprintf("%s/cosmos/auth/v1beta1/accounts/%s", c.baseURL, address)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("maya: failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("maya: failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("maya: unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var lcdResp lcdAccountResponse
	if err := json.NewDecoder(resp.Body).Decode(&lcdResp); err != nil {
		return nil, fmt.Errorf("maya: failed to decode response: %w", err)
	}

	accountNumber, err := strconv.ParseUint(lcdResp.Account.AccountNumber, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("maya: failed to parse account number: %w", err)
	}

	sequence, err := strconv.ParseUint(lcdResp.Account.Sequence, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("maya: failed to parse sequence: %w", err)
	}

	return &AccountInfo{
		Address:       lcdResp.Account.Address,
		AccountNumber: accountNumber,
		Sequence:      sequence,
	}, nil
}

// GetLatestBlock fetches the latest block information from MayaChain
func (c *Client) GetLatestBlock(ctx context.Context) (*BlockInfo, error) {
	url := fmt.Sprintf("%s/cosmos/base/tendermint/v1beta1/blocks/latest", c.baseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("maya: failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("maya: failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("maya: unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var lcdResp lcdBlockResponse
	if err := json.NewDecoder(resp.Body).Decode(&lcdResp); err != nil {
		return nil, fmt.Errorf("maya: failed to decode response: %w", err)
	}

	height, err := strconv.ParseInt(lcdResp.Block.Header.Height, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("maya: failed to parse block height: %w", err)
	}

	return &BlockInfo{
		Height: height,
	}, nil
}

