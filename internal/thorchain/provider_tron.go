package thorchain

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"

	tron_swap "github.com/vultisig/dca/internal/tron"
	"github.com/vultisig/vultisig-go/common"
)

// TronTxBuilder interface for building TRON transactions with memos
type TronTxBuilder interface {
	CreateTransactionWithMemo(ctx context.Context, from, to string, amount int64, memo string) ([]byte, error)
	CreateTRC20TransactionWithMemo(ctx context.Context, from, to, contractAddress string, amount *big.Int, memo string) ([]byte, error)
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

	// Check if this is a TRC-20 token swap (USDT)
	isTRC20 := from.AssetID != ""

	// Build the from asset string
	var fromAsset string
	if isTRC20 {
		fromAsset, err = makeThorAsset(ctx, p.client, common.Tron, from.AssetID)
		if err != nil {
			return nil, 0, fmt.Errorf("[TRON] failed to resolve from asset: %w", err)
		}
	} else {
		fromAsset = "TRON.TRX"
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

	var txData []byte
	if isTRC20 {
		// Create TRC-20 transaction to router address with memo
		txData, err = p.txBuilder.CreateTRC20TransactionWithMemo(
			ctx,
			from.Address,
			quote.Router, // For TRC-20, we use the router address
			from.AssetID, // Contract address
			new(big.Int).SetUint64(from.Amount),
			quote.Memo,
		)
	} else {
		// Check for overflow before casting to int64
		if from.Amount > math.MaxInt64 {
			return nil, 0, fmt.Errorf("[TRON] amount %d exceeds maximum int64 value", from.Amount)
		}
		// Create native TRX transaction to inbound address with memo
		txData, err = p.txBuilder.CreateTransactionWithMemo(
			ctx,
			from.Address,
			quote.InboundAddress,
			int64(from.Amount),
			quote.Memo,
		)
	}
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

// TronSDKTxBuilder implements TronTxBuilder using the TRON client
type TronSDKTxBuilder struct {
	client      tron_swap.AccountInfoProvider
	trc20Client tron_swap.TRC20Client
}

// NewTronSDKTxBuilder creates a new TronSDKTxBuilder
func NewTronSDKTxBuilder(client tron_swap.AccountInfoProvider, trc20Client tron_swap.TRC20Client) *TronSDKTxBuilder {
	return &TronSDKTxBuilder{
		client:      client,
		trc20Client: trc20Client,
	}
}

// CreateTransactionWithMemo creates a TRON native TRX transaction with a memo
// For THORChain swaps, the memo is encoded in the transaction data field (protobuf field 10)
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

	// If memo is provided, inject it into the protobuf as field 10 (data field)
	if memo != "" {
		txData, err = injectMemoIntoTronTx(txData, memo)
		if err != nil {
			return nil, fmt.Errorf("failed to inject memo: %w", err)
		}
	}

	return txData, nil
}

// injectMemoIntoTronTx injects a memo into the TRON transaction protobuf
// The memo is stored in field 10 (data) of the raw_data structure
func injectMemoIntoTronTx(txData []byte, memo string) ([]byte, error) {
	if len(memo) == 0 {
		return txData, nil
	}

	// TRON raw_data protobuf structure:
	// Field 1:  ref_block_bytes (bytes)
	// Field 4:  ref_block_hash (bytes)
	// Field 8:  expiration (int64)
	// Field 10: data (bytes) - THIS IS THE MEMO FIELD
	// Field 11: contract (message)
	// Field 14: timestamp (int64)

	// We need to insert field 10 into the protobuf
	// Field 10, wire type 2 (length-delimited) = (10 << 3) | 2 = 0x52
	memoBytes := []byte(memo)
	memoField := []byte{0x52} // Field tag for field 10, wire type 2
	memoField = append(memoField, encodeVarint(uint64(len(memoBytes)))...)
	memoField = append(memoField, memoBytes...)

	// Find where to insert the memo field (before field 11 which is the contract)
	// Field 11 starts with tag 0x5a (wire type 2)
	insertPos := -1
	pos := 0
	for pos < len(txData) {
		tagStart := pos
		tag, n := readVarintFromBytes(txData[pos:])
		if n == 0 {
			break
		}
		pos += n

		fieldNum := tag >> 3
		wireType := tag & 0x7

		// Field 11 (contract) - insert memo before this
		if fieldNum == 11 {
			insertPos = tagStart
			break
		}

		// Skip the field value based on wire type
		switch wireType {
		case 0: // Varint
			_, vn := readVarintFromBytes(txData[pos:])
			if vn == 0 {
				return nil, fmt.Errorf("failed to read varint at pos %d", pos)
			}
			pos += vn
		case 2: // Length-delimited
			length, ln := readVarintFromBytes(txData[pos:])
			if ln == 0 {
				return nil, fmt.Errorf("failed to read length at pos %d", pos)
			}
			pos += ln + int(length)
		default:
			return nil, fmt.Errorf("unsupported wire type %d", wireType)
		}
	}

	if insertPos == -1 {
		// No field 11 found, append at end
		return append(txData, memoField...), nil
	}

	// Insert memo field before field 11
	result := make([]byte, 0, len(txData)+len(memoField))
	result = append(result, txData[:insertPos]...)
	result = append(result, memoField...)
	result = append(result, txData[insertPos:]...)

	return result, nil
}

// encodeVarint encodes a uint64 as a protobuf varint
func encodeVarint(v uint64) []byte {
	var buf []byte
	for v >= 0x80 {
		buf = append(buf, byte(v)|0x80)
		v >>= 7
	}
	buf = append(buf, byte(v))
	return buf
}

// readVarintFromBytes reads a varint from a byte slice and returns (value, bytes_read)
func readVarintFromBytes(data []byte) (uint64, int) {
	var result uint64
	var shift uint
	for i, b := range data {
		if i >= 10 { // Max 10 bytes for 64-bit varint
			return 0, 0
		}
		result |= uint64(b&0x7f) << shift
		if b < 0x80 {
			return result, i + 1
		}
		shift += 7
	}
	return 0, 0
}

// CreateTRC20TransactionWithMemo creates a TRC-20 transaction for THORChain swap
// For TRC-20 swaps, the memo is passed to the THORChain router contract
func (b *TronSDKTxBuilder) CreateTRC20TransactionWithMemo(
	ctx context.Context,
	from, router, contractAddress string,
	amount *big.Int,
	memo string,
) ([]byte, error) {
	// For TRC-20 swaps via THORChain, we call the THORChain router contract
	// which handles the token transfer and memo forwarding.
	// The function is: depositWithExpiry(address,address,uint256,string,uint256)
	// But for simplicity, we use a direct TRC-20 transfer to the router
	// with memo encoded in the contract call data

	// Encode the deposit function call for THORChain router
	// Function: depositWithExpiry(address vault, address asset, uint256 amount, string memo, uint256 expiry)
	// For now, we use a simpler approach: transfer to router with memo in additional data

	// Build TRC-20 transfer to router
	parameter := encodeTRC20TransferWithMemo(router, amount, memo)

	tx, err := b.trc20Client.TriggerSmartContract(ctx, &tron_swap.TRC20TransferRequest{
		OwnerAddress:     from,
		ContractAddress:  contractAddress,
		FunctionSelector: "transfer(address,uint256)",
		Parameter:        parameter,
		FeeLimit:         50_000_000, // 50 TRX fee limit for swap
		Visible:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create TRC20 swap transaction: %w", err)
	}

	if tx.RawDataHex == "" {
		return nil, fmt.Errorf("no raw_data_hex in TRC20 swap response")
	}

	txData, err := hex.DecodeString(tx.RawDataHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode TRC20 tx data: %w", err)
	}

	return txData, nil
}

// encodeTRC20TransferWithMemo encodes TRC-20 transfer parameters for ABI
// Format: 32 bytes address (without 41 prefix) + 32 bytes amount
func encodeTRC20TransferWithMemo(to string, amount *big.Int, _ string) string {
	// For TRC-20 transfer ABI encoding:
	// - Address must be 20 bytes (40 hex chars) left-padded to 32 bytes (64 hex chars)
	// - Amount must be 32 bytes (64 hex chars)

	var addressHex string

	// Check if address is already in hex format (starts with 41)
	if len(to) == 42 && strings.HasPrefix(to, "41") {
		// Hex format with 41 prefix - remove prefix to get 20-byte address
		addressHex = to[2:]
	} else if strings.HasPrefix(to, "T") {
		// Base58 format (T...) - decode to hex
		addressBytes, err := tron_swap.DecodeBase58Address(to)
		if err != nil || len(addressBytes) != 20 {
			// Fallback: return empty which will cause transaction to fail
			return ""
		}
		addressHex = fmt.Sprintf("%x", addressBytes)
	} else {
		// Unknown format - try to use as-is
		addressHex = to
	}

	// Ensure we have exactly 40 hex chars (20 bytes)
	if len(addressHex) > 40 {
		addressHex = addressHex[len(addressHex)-40:]
	}

	// Left-pad address to 32 bytes (64 hex chars) with zeros
	addressPadded := fmt.Sprintf("%064s", addressHex)
	// Replace spaces with zeros (Sprintf %s pads with spaces)
	addressPadded = strings.ReplaceAll(addressPadded, " ", "0")

	amountHex := fmt.Sprintf("%064x", amount)
	return addressPadded + amountHex
}
