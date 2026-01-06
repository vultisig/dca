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
	parameter, err := encodeTransferParams(to, amount)
	if err != nil {
		return nil, "", fmt.Errorf("tron: failed to encode transfer params: %w", err)
	}

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

// encodeTransferParams encodes the parameters for TRC-20 transfer function
// Format: 32 bytes address (20 bytes left-padded) + 32 bytes amount
func encodeTransferParams(to string, amount *big.Int) (string, error) {
	// Convert address to 20-byte hex format for ABI encoding
	// The Parameter field is encoded locally, so we must handle Base58 conversion
	addressHex, err := addressTo20ByteHex(to)
	if err != nil {
		return "", err
	}

	// Left-pad address to 32 bytes (64 hex chars) with zeros
	addressPadded := fmt.Sprintf("%064s", addressHex)
	addressPadded = strings.ReplaceAll(addressPadded, " ", "0")

	// Pad amount to 32 bytes
	amountHex := fmt.Sprintf("%064x", amount)

	return addressPadded + amountHex, nil
}

// addressTo20ByteHex converts a TRON address (Base58 or hex) to 20-byte hex
func addressTo20ByteHex(addr string) (string, error) {
	// Check if address is already in hex format (starts with 41)
	if len(addr) == 42 && strings.HasPrefix(addr, "41") {
		// Hex format with 41 prefix - remove prefix to get 20-byte address
		return addr[2:], nil
	}

	// Base58 format (T...) - decode to hex
	if strings.HasPrefix(addr, "T") {
		addressBytes, err := DecodeBase58Address(addr)
		if err != nil {
			return "", fmt.Errorf("tron: failed to decode base58 address: %w", err)
		}
		if len(addressBytes) != 20 {
			return "", fmt.Errorf("tron: invalid address length: expected 20 bytes, got %d", len(addressBytes))
		}
		return hex.EncodeToString(addressBytes), nil
	}

	return "", fmt.Errorf("tron: unknown address format: %s", addr)
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

