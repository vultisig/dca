package rune

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

// AccountInfo represents THORChain account information
type AccountInfo struct {
	AccountNumber uint64
	Sequence      uint64
	Balance       uint64
}

// AccountInfoProvider interface defines methods for fetching THORChain account data
type AccountInfoProvider interface {
	GetAccount(ctx context.Context, address string) (*AccountInfo, error)
}

// Client implements AccountInfoProvider for THORChain
type Client struct {
	baseURL string
}

// NewClient creates a new THORChain client
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
	}
}

// accountResponse represents the response from the THORChain auth/accounts endpoint
type accountResponse struct {
	Account struct {
		Type  string `json:"@type"`
		Value struct {
			Address       string `json:"address"`
			AccountNumber string `json:"account_number"`
			Sequence      string `json:"sequence"`
		} `json:"value,omitempty"`
		// New format for Cosmos SDK accounts
		Address       string `json:"address,omitempty"`
		AccountNumber string `json:"account_number,omitempty"`
		Sequence      string `json:"sequence,omitempty"`
	} `json:"account"`
}

// GetAccount fetches account information from THORChain
func (c *Client) GetAccount(ctx context.Context, address string) (*AccountInfo, error) {
	url := fmt.Sprintf("%s/cosmos/auth/v1beta1/accounts/%s", c.baseURL, address)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("rune: failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rune: failed to get account: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("rune: account request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var accResp accountResponse
	if err := json.NewDecoder(resp.Body).Decode(&accResp); err != nil {
		return nil, fmt.Errorf("rune: failed to decode account response: %w", err)
	}

	// Handle both old and new account response formats
	accountNumStr := accResp.Account.AccountNumber
	sequenceStr := accResp.Account.Sequence
	if accountNumStr == "" {
		accountNumStr = accResp.Account.Value.AccountNumber
	}
	if sequenceStr == "" {
		sequenceStr = accResp.Account.Value.Sequence
	}

	accountNum, err := strconv.ParseUint(accountNumStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("rune: failed to parse account number: %w", err)
	}

	sequence, err := strconv.ParseUint(sequenceStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("rune: failed to parse sequence: %w", err)
	}

	balance, err := c.getRuneBalance(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("rune: failed to get balance: %w", err)
	}

	return &AccountInfo{
		AccountNumber: accountNum,
		Sequence:      sequence,
		Balance:       balance,
	}, nil
}

type balanceResponse struct {
	Balances []struct {
		Denom  string `json:"denom"`
		Amount string `json:"amount"`
	} `json:"balances"`
}

func (c *Client) getRuneBalance(ctx context.Context, address string) (uint64, error) {
	url := fmt.Sprintf("%s/cosmos/bank/v1beta1/balances/%s", c.baseURL, address)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to get balance: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("balance request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var balResp balanceResponse
	err = json.NewDecoder(resp.Body).Decode(&balResp)
	if err != nil {
		return 0, fmt.Errorf("failed to decode balance response: %w", err)
	}

	for _, bal := range balResp.Balances {
		if bal.Denom == "rune" {
			balance, err := strconv.ParseUint(bal.Amount, 10, 64)
			if err != nil {
				return 0, fmt.Errorf("failed to parse balance: %w", err)
			}
			return balance, nil
		}
	}

	return 0, nil
}

