package cosmos

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/vultisig/verifier/plugin/libhttp"
)

// AccountInfoProvider interface defines methods for fetching Cosmos account and network data
type AccountInfoProvider interface {
	GetAccount(ctx context.Context, address string) (*AccountInfo, error)
	GetLatestBlock(ctx context.Context) (*BlockInfo, error)
}

// AccountInfo represents Cosmos account information
type AccountInfo struct {
	Address       string `json:"address"`
	AccountNumber uint64 `json:"account_number"`
	Sequence      uint64 `json:"sequence"`
}

// BlockInfo represents Cosmos block information
type BlockInfo struct {
	Height int64 `json:"height"`
}

// Client implements AccountInfoProvider using Cosmos LCD API
type Client struct {
	baseURL string
}

// NewClient creates a new Cosmos client with the given LCD URL
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
	}
}

// lcdAccountResponse represents the Cosmos LCD API response for account query
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

// lcdBlockResponse represents the Cosmos LCD API response for block query
type lcdBlockResponse struct {
	Block struct {
		Header struct {
			Height string `json:"height"`
		} `json:"header"`
	} `json:"block"`
}

// GetAccount fetches account information from Cosmos chain
func (c *Client) GetAccount(ctx context.Context, address string) (*AccountInfo, error) {
	url := fmt.Sprintf("%s/cosmos/auth/v1beta1/accounts/%s", c.baseURL, address)

	lcdResp, err := libhttp.Call[lcdAccountResponse](ctx, http.MethodGet, url, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("cosmos: failed to get account: %w", err)
	}

	accountNumber, err := strconv.ParseUint(lcdResp.Account.AccountNumber, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("cosmos: failed to parse account number: %w", err)
	}

	sequence, err := strconv.ParseUint(lcdResp.Account.Sequence, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("cosmos: failed to parse sequence: %w", err)
	}

	return &AccountInfo{
		Address:       lcdResp.Account.Address,
		AccountNumber: accountNumber,
		Sequence:      sequence,
	}, nil
}

// GetLatestBlock fetches the latest block information from Cosmos chain
func (c *Client) GetLatestBlock(ctx context.Context) (*BlockInfo, error) {
	url := fmt.Sprintf("%s/cosmos/base/tendermint/v1beta1/blocks/latest", c.baseURL)

	lcdResp, err := libhttp.Call[lcdBlockResponse](ctx, http.MethodGet, url, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("cosmos: failed to get latest block: %w", err)
	}

	height, err := strconv.ParseInt(lcdResp.Block.Header.Height, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("cosmos: failed to parse block height: %w", err)
	}

	return &BlockInfo{
		Height: height,
	}, nil
}
