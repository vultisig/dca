package thorchain

import (
	"context"
	"fmt"
	"strconv"

	thorchain_native "github.com/vultisig/dca/internal/thorchain_native"
	"github.com/vultisig/vultisig-go/common"
)

// ProviderThorchainNative implements thorchain_native.SwapProvider interface
// It uses THORChain API for quotes and builds native THORChain transactions
type ProviderThorchainNative struct {
	client           *Client
	thorchainClient  thorchain_native.AccountInfoProvider
}

// Ensure ProviderThorchainNative implements thorchain_native.SwapProvider
var _ thorchain_native.SwapProvider = (*ProviderThorchainNative)(nil)

func NewProviderThorchainNative(client *Client, thorchainClient thorchain_native.AccountInfoProvider) *ProviderThorchainNative {
	return &ProviderThorchainNative{
		client:          client,
		thorchainClient: thorchainClient,
	}
}

func (p *ProviderThorchainNative) validateThorchainNative(from thorchain_native.From, to thorchain_native.To) error {
	if from.Address == "" {
		return fmt.Errorf("[THORChain] from address cannot be empty")
	}

	if to.Address == "" {
		return fmt.Errorf("[THORChain] to address cannot be empty")
	}

	// Validate destination chain is supported
	_, err := parseThorNetwork(to.Chain)
	if err != nil {
		return fmt.Errorf("[THORChain] unsupported destination chain: %w", err)
	}

	return nil
}

func (p *ProviderThorchainNative) MakeTransaction(
	ctx context.Context,
	from thorchain_native.From,
	to thorchain_native.To,
) ([]byte, uint64, error) {
	if err := p.validateThorchainNative(from, to); err != nil {
		return nil, 0, fmt.Errorf("[THORChain] invalid swap: %w", err)
	}

	// Convert assets to THORChain format
	fromAsset, err := makeThorAsset(ctx, p.client, common.THORChain, from.AssetID)
	if err != nil {
		return nil, 0, fmt.Errorf("[THORChain] failed to convert from asset: %w", err)
	}

	toAsset, err := makeThorAsset(ctx, p.client, to.Chain, to.AssetID)
	if err != nil {
		return nil, 0, fmt.Errorf("[THORChain] failed to convert to asset: %w", err)
	}

	// Get quote from THORChain for the swap
	quote, err := p.client.getQuote(ctx, quoteSwapRequest{
		FromAsset:         fromAsset,
		ToAsset:           toAsset,
		Amount:            fmt.Sprintf("%d", from.Amount),
		Destination:       to.Address,
		StreamingInterval: defaultStreamingInterval,
		StreamingQuantity: defaultStreamingQuantity,
		ToleranceBps:      defaultToleranceBps,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("[THORChain] failed to get quote: %w", err)
	}

	// Parse expected amount out
	expectedOut, err := strconv.ParseUint(quote.ExpectedAmountOut, 10, 64)
	if err != nil {
		return nil, 0, fmt.Errorf("[THORChain] failed to parse expected amount out: %w", err)
	}

	// Get dynamic THORChain network data
	currentHeight, err := p.thorchainClient.GetLatestBlock(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("[THORChain] failed to get current block height: %w", err)
	}

	baseFee, err := p.thorchainClient.GetBaseFee(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("[THORChain] failed to get base fee: %w", err)
	}

	// Get account sequence for the from address
	sequence, err := p.thorchainClient.GetAccountInfo(ctx, from.Address)
	if err != nil {
		return nil, 0, fmt.Errorf("[THORChain] failed to get account sequence: %w", err)
	}

	// Build THORChain native swap transaction
	txBytes, err := buildUnsignedThorchainSwapTx(
		from,
		to,
		quote,
		sequence,
		baseFee,
		currentHeight+100, // 100 block buffer
	)
	if err != nil {
		return nil, 0, fmt.Errorf("[THORChain] failed to build swap transaction: %w", err)
	}

	return txBytes, expectedOut, nil
}

// buildUnsignedThorchainSwapTx creates an unsigned THORChain swap transaction
func buildUnsignedThorchainSwapTx(
	from thorchain_native.From,
	to thorchain_native.To,
	quote quoteSwapResponse,
	sequence uint64,
	feeRune uint64,
	timeoutHeight uint64,
) ([]byte, error) {
	// TODO: Implement actual Cosmos SDK transaction building for THORChain
	// This would involve:
	// 1. Creating appropriate THORChain swap message (MsgSwap or MsgSend to vault)
	// 2. Building Cosmos SDK transaction with proper fee, sequence, timeout
	// 3. Serializing to protobuf bytes for signing
	
	// Determine swap type based on destination
	var swapType string
	var memo string
	
	if to.Chain == common.THORChain {
		// Native THORChain swap (e.g., RUNE to synthetic asset)
		swapType = "native-swap"
		memo = fmt.Sprintf("=:%s:%s", quote.Memo, to.Address)
	} else {
		// Cross-chain swap (e.g., RUNE to external chain)
		swapType = "cross-chain-swap" 
		memo = quote.Memo
	}
	
	// For now, return a structured placeholder that indicates the transaction details
	placeholder := fmt.Sprintf("thorchain-tx:type=%s:from=%s:to=%s:amount=%d:sequence=%d:fee=%d:timeout=%d:memo=%s:pubkey=%s",
		swapType, from.Address, to.Address, from.Amount, sequence, feeRune, timeoutHeight, memo, from.PubKey)
	
	return []byte(placeholder), nil
}