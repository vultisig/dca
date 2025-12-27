package xrp

import (
	"context"
	"fmt"
)

type SendService struct {
	client AccountInfoProvider
}

func NewSendService(client AccountInfoProvider) *SendService {
	return &SendService{
		client: client,
	}
}

func (s *SendService) BuildPayment(
	ctx context.Context,
	from string,
	to string,
	amountDrops uint64,
	signingPubKey string,
) ([]byte, error) {
	// Get dynamic XRP network data
	sequence, err := s.client.GetAccountInfo(ctx, from)
	if err != nil {
		return nil, fmt.Errorf("failed to get account sequence: %w", err)
	}

	return s.BuildPaymentWithSequence(ctx, from, to, amountDrops, signingPubKey, sequence)
}

// BuildPaymentWithSequence builds a payment transaction with a specified sequence number.
// Use this for multi-recipient sends where sequence must be incremented for each tx.
func (s *SendService) BuildPaymentWithSequence(
	ctx context.Context,
	from string,
	to string,
	amountDrops uint64,
	signingPubKey string,
	sequence uint32,
) ([]byte, error) {
	currentLedger, err := s.client.GetCurrentLedger(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get current ledger: %w", err)
	}

	baseFee, err := s.client.GetBaseFee(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get base fee: %w", err)
	}

	// Build simple payment transaction
	txData, err := buildUnsignedXRPLSimplePayment(
		from,
		to,
		amountDrops,
		sequence,
		baseFee,
		currentLedger+100, // 100 ledger buffer (~5 minutes)
		signingPubKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build payment transaction: %w", err)
	}

	return txData, nil
}

// GetSequence fetches the current account sequence number.
func (s *SendService) GetSequence(ctx context.Context, address string) (uint32, error) {
	return s.client.GetAccountInfo(ctx, address)
}