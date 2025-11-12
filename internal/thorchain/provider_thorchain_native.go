package thorchain

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"

	"cosmossdk.io/math"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	thorchain_native "github.com/vultisig/dca/internal/thorchain_native"
	recipestypes "github.com/vultisig/recipes/types"
	"github.com/vultisig/vultisig-go/common"
)

// ProviderThorchainNative implements thorchain_native.SwapProvider interface
// It uses THORChain API for quotes and builds native THORChain transactions
type ProviderThorchainNative struct {
	client          *Client
	thorchainClient *thorchain_native.Client
}

// Ensure ProviderThorchainNative implements thorchain_native.SwapProvider
var _ thorchain_native.SwapProvider = (*ProviderThorchainNative)(nil)

func NewProviderThorchainNative(client *Client, thorchainClient *thorchain_native.Client) *ProviderThorchainNative {
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

	// Only allow cross-chain swaps for now (reject same-chain THORChain swaps)
	if to.Chain == common.THORChain {
		return fmt.Errorf("[THORChain] same-chain swaps not supported - only cross-chain swaps allowed (THORChain to external chains)")
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
	quoteRequest := quoteSwapRequest{
		FromAsset:         fromAsset,
		ToAsset:           toAsset,
		Amount:            fmt.Sprintf("%d", from.Amount),
		Destination:       to.Address,
		StreamingInterval: defaultStreamingInterval,
		StreamingQuantity: defaultStreamingQuantity,
		ToleranceBps:      defaultToleranceBps,
	}

	quote, err := p.client.getQuote(ctx, quoteRequest)
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

	// Get complete account information (number and sequence) from the from address
	accountInfo, err := p.thorchainClient.GetAccountInfo(ctx, from.Address)
	if err != nil {
		return nil, 0, fmt.Errorf("[THORChain] failed to get account info: %w", err)
	}

	// Build THORChain native swap transaction
	txBytes, err := buildUnsignedThorchainSwapTx(
		from,
		quote,
		accountInfo,
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
	quote quoteSwapResponse,
	accountInfo thorchain_native.AccountInfo, // Account number and sequence are needed for proper SignDoc
	feeRune uint64, // Base fee in RUNE (from GetBaseFee)
	_ uint64, // timeoutHeight - not needed for MsgDeposit
) ([]byte, error) {
	// Build THORChain memo for cross-chain swap
	// Since we only support cross-chain swaps, use the quote memo directly
	memo := quote.Memo

	// Create the asset based on the from.AssetID
	var asset *recipestypes.Asset
	var decimals int64
	
	if from.AssetID == "" {
		// Native RUNE
		asset = &recipestypes.Asset{
			Chain:   "THOR",
			Symbol:  "RUNE",
			Ticker:  "RUNE",
			Synth:   false,
			Trade:   false,
			Secured: false,
		}
		decimals = 8 // RUNE has 8 decimals
	} else {
		// Other THORChain assets (e.g., tokens)
		asset = &recipestypes.Asset{
			Chain:   "THOR",
			Symbol:  from.AssetID,
			Ticker:  from.AssetID,
			Synth:   false,
			Trade:   false,
			Secured: false,
		}
		decimals = 8 // Default to 8 decimals for THORChain assets
	}

	// Create the deposit coin using the new Coin structure (no denom field)
	coin := &recipestypes.Coin{
		Asset:    asset,
		Amount:   fmt.Sprintf("%d", from.Amount),
		Decimals: decimals,
	}

	// Decode bech32 address to raw address bytes (not ASCII bytes)
	signerBytes, err := sdk.GetFromBech32(from.Address, "thor")
	if err != nil {
		return nil, fmt.Errorf("failed to decode bech32 address %s: %w", from.Address, err)
	}

	// Build MsgDeposit with memo in the message (correct for cross-chain swaps)
	msgDeposit := &recipestypes.MsgDeposit{
		Coins:  []*recipestypes.Coin{coin},
		Memo:   memo,        // Memo goes in MsgDeposit for cross-chain swaps
		Signer: signerBytes, // Signer as bytes instead of string
	}

	// Pack MsgDeposit into Any for Cosmos SDK transaction
	msgAny, err := codectypes.NewAnyWithValue(msgDeposit)
	if err != nil {
		return nil, fmt.Errorf("failed to pack MsgDeposit into Any: %w", err)
	}

	// Convert public key hex string to secp256k1.PubKey (now properly registered)
	pubKeyBytes, err := hex.DecodeString(from.PubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key hex: %w", err)
	}

	pubKey := &secp256k1.PubKey{Key: pubKeyBytes}
	pubKeyAny, err := codectypes.NewAnyWithValue(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to pack public key into Any: %w", err)
	}

	// Create fee amount using dynamic fee from THORChain network
	feeAmount := sdk.NewCoins(sdk.NewCoin("rune", math.NewInt(int64(feeRune))))
	// TODO consider fetching dynamically
	gasLimit := uint64(500000) // 500k gas limit

	// Create complete Cosmos SDK transaction structure with proper gas and fees
	// For MsgDeposit, memo goes in the message, not transaction body
	txData := &tx.Tx{
		Body: &tx.TxBody{
			Messages: []*codectypes.Any{msgAny},
			Memo:     "", // Empty for MsgDeposit - memo is in the message
		},
		AuthInfo: &tx.AuthInfo{
			SignerInfos: []*tx.SignerInfo{
				{
					PublicKey: pubKeyAny,
					ModeInfo: &tx.ModeInfo{
						Sum: &tx.ModeInfo_Single_{
							Single: &tx.ModeInfo_Single{
								Mode: signing.SignMode_SIGN_MODE_DIRECT,
							},
						},
					},
					Sequence: accountInfo.Sequence, // Use actual account sequence from chain
				},
			},
			Fee: &tx.Fee{
				Amount:   feeAmount,
				GasLimit: gasLimit,
			},
		},
		Signatures: [][]byte{{}}, // Empty signature placeholder for unsigned transaction
	}

	// Create codec interface registry and register types
	ir := codectypes.NewInterfaceRegistry()
	// Register crypto types (including secp256k1 public keys)
	cryptocodec.RegisterInterfaces(ir)
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
