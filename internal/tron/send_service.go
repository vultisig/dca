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
// Format: 32 bytes address (20 bytes left-padded) + 32 bytes amount
func encodeTRC20TransferParameter(to string, amount *big.Int) string {
	// For TRC-20 transfer ABI encoding with visible=true:
	// TronGrid handles the address format conversion internally
	// We pass the address as-is since visible=true is set in the request
	// The API will convert T... addresses to proper hex format

	// For addresses already in hex format (41...), extract the 20-byte portion
	addressHex := to
	if len(addressHex) == 42 && strings.HasPrefix(addressHex, "41") {
		// Remove 41 prefix to get 20-byte address (40 hex chars)
		addressHex = addressHex[2:]
	}

	// Left-pad address to 32 bytes (64 hex chars) with zeros
	// Note: When visible=true, TronGrid handles T... addresses
	addressPadded := fmt.Sprintf("%064s", addressHex)
	// Replace spaces with zeros (Sprintf %s pads with spaces, not zeros)
	addressPadded = strings.ReplaceAll(addressPadded, " ", "0")

	// Pad amount to 32 bytes
	amountHex := fmt.Sprintf("%064x", amount)

	return addressPadded + amountHex
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

