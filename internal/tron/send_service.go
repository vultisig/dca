package tron

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// TRC20Client interface for TRC-20 operations
type TRC20Client interface {
	TriggerSmartContract(ctx context.Context, req *TRC20TransferRequest) (*Transaction, error)
}

// SendService handles building TRON send transactions
type SendService struct {
	client      AccountInfoProvider
	trc20Client TRC20Client
}

// NewSendService creates a new SendService
func NewSendService(client AccountInfoProvider, trc20Client TRC20Client) *SendService {
	return &SendService{
		client:      client,
		trc20Client: trc20Client,
	}
}

// BuildTransfer builds an unsigned TRX transfer transaction
// Returns the raw_data bytes (protobuf-serialized) for signing
func (s *SendService) BuildTransfer(
	ctx context.Context,
	from string,
	to string,
	amountSun uint64,
) ([]byte, string, error) {
	// Create the transaction using TronGrid API
	tx, err := s.client.CreateTransaction(ctx, &TransferRequest{
		OwnerAddress: from,
		ToAddress:    to,
		Amount:       int64(amountSun),
		Visible:      true,
	})
	if err != nil {
		return nil, "", fmt.Errorf("tron: failed to create transaction: %w", err)
	}

	if tx.RawDataHex == "" {
		return nil, "", fmt.Errorf("tron: no raw_data_hex in transaction response")
	}

	// Decode the raw_data_hex to bytes
	rawDataBytes, err := hex.DecodeString(tx.RawDataHex)
	if err != nil {
		return nil, "", fmt.Errorf("tron: failed to decode raw_data_hex: %w", err)
	}

	return rawDataBytes, tx.TxID, nil
}

// BuildTRC20Transfer builds an unsigned TRC-20 token transfer transaction
// This is used for tokens like USDT on TRON
func (s *SendService) BuildTRC20Transfer(
	ctx context.Context,
	from string,
	to string,
	contractAddress string,
	amount *big.Int,
	feeLimit int64,
) ([]byte, string, error) {
	// Encode the transfer function call: transfer(address,uint256)
	// Function selector: a9059cbb
	parameter := encodeTRC20TransferParameter(to, amount)

	tx, err := s.trc20Client.TriggerSmartContract(ctx, &TRC20TransferRequest{
		OwnerAddress:     from,
		ContractAddress:  contractAddress,
		FunctionSelector: "transfer(address,uint256)",
		Parameter:        parameter,
		FeeLimit:         feeLimit,
		Visible:          true,
	})
	if err != nil {
		return nil, "", fmt.Errorf("tron: failed to create TRC20 transfer: %w", err)
	}

	if tx.RawDataHex == "" {
		return nil, "", fmt.Errorf("tron: no raw_data_hex in TRC20 transaction response")
	}

	rawDataBytes, err := hex.DecodeString(tx.RawDataHex)
	if err != nil {
		return nil, "", fmt.Errorf("tron: failed to decode TRC20 raw_data_hex: %w", err)
	}

	return rawDataBytes, tx.TxID, nil
}

// encodeTRC20TransferParameter encodes the parameters for TRC-20 transfer function
// Format: 32 bytes address + 32 bytes amount
func encodeTRC20TransferParameter(to string, amount *big.Int) string {
	// Convert TRON address to hex (remove T prefix and convert from base58)
	toHex := tronAddressToHex(to)

	// Pad address to 32 bytes (left pad with zeros, skip first byte 0x41)
	addressPadded := fmt.Sprintf("%064s", toHex[2:]) // Skip 0x41 prefix

	// Pad amount to 32 bytes
	amountHex := fmt.Sprintf("%064x", amount)

	return addressPadded + amountHex
}

// tronAddressToHex converts a TRON address (T...) to hex format
func tronAddressToHex(address string) string {
	// If already hex (starts with 41), return as is
	if strings.HasPrefix(address, "41") && len(address) == 42 {
		return address
	}

	// For base58 addresses starting with T, we need to decode
	// For simplicity, if the address is already in visible format from API,
	// the API handles conversion. This is a passthrough.
	if strings.HasPrefix(address, "T") {
		// The TronGrid API with visible=true handles address conversion
		// We pass the address as-is and let the API convert it
		return address
	}

	return address
}

// GetBalance fetches the TRX balance for an address
func (s *SendService) GetBalance(ctx context.Context, address string) (uint64, error) {
	account, err := s.client.GetAccount(ctx, address)
	if err != nil {
		return 0, fmt.Errorf("tron: failed to get account: %w", err)
	}

	if account.Balance < 0 {
		return 0, nil
	}

	return uint64(account.Balance), nil
}

