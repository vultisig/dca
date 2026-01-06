package tron

import (
	"context"
	"encoding/hex"
	"fmt"
)

// SendService handles building TRON send transactions
type SendService struct {
	client AccountInfoProvider
}

// NewSendService creates a new SendService
func NewSendService(client AccountInfoProvider) *SendService {
	return &SendService{
		client: client,
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

