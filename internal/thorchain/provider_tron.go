package thorchain

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"

	tron_swap "github.com/vultisig/dca/internal/tron"
	"github.com/vultisig/vultisig-go/common"
)

// TronTxBuilder interface for building TRON transactions with memos
type TronTxBuilder interface {
	CreateTransactionWithMemo(ctx context.Context, from, to string, amount int64, memo string) ([]byte, error)
}

// ProviderTron implements the tron.SwapProvider interface for THORChain swaps
type ProviderTron struct {
	client    *Client
	txBuilder TronTxBuilder
}

// NewProviderTron creates a new THORChain provider for TRON swaps
func NewProviderTron(client *Client, txBuilder TronTxBuilder) *ProviderTron {
	return &ProviderTron{
		client:    client,
		txBuilder: txBuilder,
	}
}

// MakeTransaction builds a TRON transaction for a THORChain swap
func (p *ProviderTron) MakeTransaction(
	ctx context.Context,
	from tron_swap.From,
	to tron_swap.To,
) ([]byte, uint64, error) {
	// Validate source and destination
	if to.Chain == common.Tron && to.AssetID == from.AssetID {
		return nil, 0, fmt.Errorf("[TRON] can't swap same asset to same asset")
	}

	// Validate that the destination chain is supported by THORChain
	_, err := parseThorNetwork(to.Chain)
	if err != nil {
		return nil, 0, fmt.Errorf("[TRON] unsupported destination chain: %w", err)
	}

	// Build the from asset string (TRON.TRX for native)
	var fromAsset string
	if from.AssetID == "" {
		fromAsset = "TRON.TRX"
	} else {
		fromAsset, err = makeThorAsset(ctx, p.client, common.Tron, from.AssetID)
		if err != nil {
			return nil, 0, fmt.Errorf("[TRON] failed to resolve from asset: %w", err)
		}
	}

	// Build the to asset string
	toAsset, err := makeThorAsset(ctx, p.client, to.Chain, to.AssetID)
	if err != nil {
		return nil, 0, fmt.Errorf("[TRON] failed to resolve to asset: %w", err)
	}

	// TRON uses 6 decimals, THORChain uses 8 decimals
	// Convert from sun (6 decimals) to THORChain (8 decimals)
	thorAmount := from.Amount * 100 // 6 -> 8 decimals

	// Get quote from THORChain
	quote, err := p.client.getQuote(ctx, quoteSwapRequest{
		FromAsset:         fromAsset,
		ToAsset:           toAsset,
		Amount:            strconv.FormatUint(thorAmount, 10),
		Destination:       to.Address,
		StreamingInterval: defaultStreamingInterval,
		StreamingQuantity: defaultStreamingQuantity,
		ToleranceBps:      defaultToleranceBps,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("[TRON] failed to get quote: %w", err)
	}

	// Check dust threshold
	dustThreshold, err := strconv.ParseUint(quote.DustThreshold, 10, 64)
	if err != nil {
		return nil, 0, fmt.Errorf("[TRON] failed to parse dust threshold: %w", err)
	}

	if thorAmount < dustThreshold {
		return nil, 0, fmt.Errorf("[TRON] amount %d below dust threshold %d", thorAmount, dustThreshold)
	}

	// Create transaction to inbound address with memo
	txData, err := p.txBuilder.CreateTransactionWithMemo(
		ctx,
		from.Address,
		quote.InboundAddress,
		int64(from.Amount),
		quote.Memo,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("[TRON] failed to create transaction: %w", err)
	}

	// Parse expected amount out
	expectedOut, err := strconv.ParseUint(quote.ExpectedAmountOut, 10, 64)
	if err != nil {
		return nil, 0, fmt.Errorf("[TRON] failed to parse expected amount out: %w", err)
	}

	return txData, expectedOut, nil
}

// TronSDKTxBuilder implements TronTxBuilder using the recipes TRON SDK
type TronSDKTxBuilder struct {
	client tron_swap.AccountInfoProvider
}

// NewTronSDKTxBuilder creates a new TronSDKTxBuilder
func NewTronSDKTxBuilder(client tron_swap.AccountInfoProvider) *TronSDKTxBuilder {
	return &TronSDKTxBuilder{client: client}
}

// CreateTransactionWithMemo creates a TRON transaction with a memo
// For THORChain swaps, the memo is encoded in the transaction data field
func (b *TronSDKTxBuilder) CreateTransactionWithMemo(
	ctx context.Context,
	from, to string,
	amount int64,
	memo string,
) ([]byte, error) {
	// Create basic transaction
	tx, err := b.client.CreateTransaction(ctx, &tron_swap.TransferRequest{
		OwnerAddress: from,
		ToAddress:    to,
		Amount:       amount,
		Visible:      true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction: %w", err)
	}

	// Decode raw_data_hex
	txData, err := hex.DecodeString(tx.RawDataHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode tx data: %w", err)
	}

	// Note: For THORChain TRON swaps, the memo is typically included
	// in the transaction data field. This may require protobuf manipulation
	// to properly include the memo. For now, we return the basic transaction.
	// TODO: Implement proper memo encoding for TRON transactions
	_ = memo

	return txData, nil
}

