package tron

import (
	"context"
	"fmt"
	"net/http"

	"github.com/vultisig/verifier/plugin/libhttp"
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
	baseURL string
}

// NewClient creates a new TRON client with the given base URL
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
	}
}

// accountRequest is the request body for GetAccount
type accountRequest struct {
	Address string `json:"address"`
	Visible bool   `json:"visible"`
}

// GetAccount fetches account information from TRON network
func (c *Client) GetAccount(ctx context.Context, address string) (*AccountInfo, error) {
	reqBody := accountRequest{
		Address: address,
		Visible: true,
	}

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	account, err := libhttp.Call[AccountInfo](ctx, http.MethodPost, c.baseURL+"/wallet/getaccount", headers, reqBody, nil)
	if err != nil {
		return nil, fmt.Errorf("tron: failed to get account: %w", err)
	}

	return &account, nil
}

// GetNowBlock fetches the current block from TRON network
func (c *Client) GetNowBlock(ctx context.Context) (*Block, error) {
	headers := map[string]string{
		"Content-Type": "application/json",
	}

	block, err := libhttp.Call[Block](ctx, http.MethodPost, c.baseURL+"/wallet/getnowblock", headers, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("tron: failed to get now block: %w", err)
	}

	return &block, nil
}

// CreateTransaction creates an unsigned TRX transfer transaction
func (c *Client) CreateTransaction(ctx context.Context, transferReq *TransferRequest) (*Transaction, error) {
	headers := map[string]string{
		"Content-Type": "application/json",
	}

	tx, err := libhttp.Call[Transaction](ctx, http.MethodPost, c.baseURL+"/wallet/createtransaction", headers, transferReq, nil)
	if err != nil {
		return nil, fmt.Errorf("tron: failed to create transaction: %w", err)
	}

	return &tx, nil
}
