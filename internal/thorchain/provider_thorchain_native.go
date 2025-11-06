package thorchain

import (
	"context"
	"fmt"
	"strconv"

	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx"
	thorchain_native "github.com/vultisig/dca/internal/thorchain_native"
	recipestypes "github.com/vultisig/recipes/types"
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
	_ uint64, // sequence - not needed for MsgDeposit, handled by THORChain SDK
	_ uint64, // feeRune - not needed for MsgDeposit, THORChain handles fees differently
	_ uint64, // timeoutHeight - not needed for MsgDeposit
) ([]byte, error) {
	// Build THORChain memo for the swap
	var memo string
	if to.Chain == common.THORChain {
		// Native THORChain swap (e.g., RUNE to synthetic asset)
		memo = fmt.Sprintf("=:%s:%s", quote.Memo, to.Address)
	} else {
		// Cross-chain swap (e.g., RUNE to external chain)
		memo = quote.Memo
	}
	
	// Create the deposit coin - for THORChain swaps, we deposit RUNE or other native assets
	coin := &recipestypes.Coin{
		Denom:  getRUNEDenom(from.AssetID), // Convert asset ID to proper denom
		Amount: fmt.Sprintf("%d", from.Amount),
	}
	
	// Build MsgDeposit (without memo - it goes in transaction body)
	msgDeposit := &recipestypes.MsgDeposit{
		Coins:  []*recipestypes.Coin{coin},
		Signer: from.Address,
		// Memo is removed from here - it goes in the transaction body
	}
	
	// Pack MsgDeposit into Any for Cosmos SDK transaction
	msgAny, err := codectypes.NewAnyWithValue(msgDeposit)
	if err != nil {
		return nil, fmt.Errorf("failed to pack MsgDeposit into Any: %w", err)
	}
	
	// Create complete Cosmos SDK transaction structure
	txData := &tx.Tx{
		Body: &tx.TxBody{
			Messages: []*codectypes.Any{msgAny},
			Memo:     memo, // Memo goes at transaction level for THORChain
		},
		AuthInfo: &tx.AuthInfo{
			// Empty for unsigned transaction
		},
		Signatures: [][]byte{}, // Empty for unsigned transaction
	}
	
	// Create codec interface registry and register types
	ir := codectypes.NewInterfaceRegistry()
	// Register the MsgDeposit as implementing sdk.Msg interface (like in recipes)
	ir.RegisterImplementations((*sdk.Msg)(nil), &recipestypes.MsgDeposit{})
	cdc := codec.NewProtoCodec(ir)
	
	// Marshal the complete transaction
	txBytes, err := cdc.Marshal(txData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal complete transaction: %w", err)
	}
	
	return txBytes, nil
}

// getRUNEDenom converts asset ID to proper THORChain denomination
func getRUNEDenom(assetID string) string {
	if assetID == "" || assetID == "RUNE" {
		return "rune" // Native RUNE
	}
	// For other assets, they would typically be in the format like "ETH.ETH-0x..."
	// but for THORChain deposits, we're usually depositing RUNE
	return "rune"
}