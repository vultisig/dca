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
	cosmostypes "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"

	cosmos_swap "github.com/vultisig/dca/internal/cosmos"
	"github.com/vultisig/vultisig-go/common"
)

const (
	cosmosGasLimit   = uint64(200000)
	cosmosFeeAmount  = "5000"
	cosmosChainID    = "cosmoshub-4"
	cosmosAtomDenom  = "uatom"
)

// ProviderCosmos implements the cosmos.SwapProvider interface for THORChain swaps
type ProviderCosmos struct {
	client *Client
	cdc    codec.Codec
}

// NewProviderCosmos creates a new THORChain provider for Cosmos swaps
func NewProviderCosmos(client *Client) *ProviderCosmos {
	ir := codectypes.NewInterfaceRegistry()
	cryptocodec.RegisterInterfaces(ir)
	banktypes.RegisterInterfaces(ir)

	return &ProviderCosmos{
		client: client,
		cdc:    codec.NewProtoCodec(ir),
	}
}

// MakeTransaction builds a Cosmos transaction for a THORChain swap
func (p *ProviderCosmos) MakeTransaction(
	ctx context.Context,
	from cosmos_swap.From,
	to cosmos_swap.To,
) (txData []byte, signBytes []byte, toAmount uint64, err error) {
	// Validate source and destination
	if to.Chain == common.GaiaChain && to.AssetID == from.AssetID {
		return nil, nil, 0, fmt.Errorf("[COSMOS] can't swap same asset to same asset")
	}

	// Validate that the destination chain is supported by THORChain
	_, err = parseThorNetwork(to.Chain)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("[COSMOS] unsupported destination chain: %w", err)
	}

	// Build the from asset string (GAIA.ATOM for native)
	var fromAsset string
	if from.AssetID == "" {
		fromAsset = "GAIA.ATOM"
	} else {
		fromAsset, err = makeThorAsset(ctx, p.client, common.GaiaChain, from.AssetID)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("[COSMOS] failed to resolve from asset: %w", err)
		}
	}

	// Build the to asset string
	toAsset, err := makeThorAsset(ctx, p.client, to.Chain, to.AssetID)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("[COSMOS] failed to resolve to asset: %w", err)
	}

	// ATOM uses 6 decimals, THORChain uses 8 decimals
	// Convert from uatom (6 decimals) to THORChain (8 decimals)
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
		return nil, nil, 0, fmt.Errorf("[COSMOS] failed to get quote: %w", err)
	}

	// Check dust threshold
	dustThreshold, err := strconv.ParseUint(quote.DustThreshold, 10, 64)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("[COSMOS] failed to parse dust threshold: %w", err)
	}

	if thorAmount < dustThreshold {
		return nil, nil, 0, fmt.Errorf("[COSMOS] amount %d below dust threshold %d", thorAmount, dustThreshold)
	}

	// Build the Cosmos transaction with memo
	txData, signBytes, err = p.buildSwapTransaction(
		from.Address,
		quote.InboundAddress,
		from.Amount,
		from.PubKey,
		from.AccountNumber,
		from.Sequence,
		quote.Memo,
	)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("[COSMOS] failed to build transaction: %w", err)
	}

	// Parse expected amount out
	expectedOut, err := strconv.ParseUint(quote.ExpectedAmountOut, 10, 64)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("[COSMOS] failed to parse expected amount out: %w", err)
	}

	return txData, signBytes, expectedOut, nil
}

// buildSwapTransaction builds a Cosmos bank send transaction with memo for THORChain
func (p *ProviderCosmos) buildSwapTransaction(
	from string,
	to string,
	amountUatom uint64,
	pubKeyHex string,
	accountNumber uint64,
	sequence uint64,
	memo string,
) ([]byte, []byte, error) {
	// Parse addresses
	fromAddr, err := cosmostypes.AccAddressFromBech32(from)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid from address: %w", err)
	}

	toAddr, err := cosmostypes.AccAddressFromBech32(to)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid to address: %w", err)
	}

	// Create send message
	amount := cosmostypes.NewCoins(cosmostypes.NewCoin(cosmosAtomDenom, math.NewIntFromUint64(amountUatom)))
	sendMsg := banktypes.NewMsgSend(fromAddr, toAddr, amount)

	// Wrap message in Any
	msgAny, err := codectypes.NewAnyWithValue(sendMsg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create message any: %w", err)
	}

	// Decode public key
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode pubkey: %w", err)
	}

	if len(pubKeyBytes) != 33 {
		return nil, nil, fmt.Errorf("invalid pubkey length: expected 33 bytes, got %d", len(pubKeyBytes))
	}

	// Create Cosmos public key
	cosmosPubKey := &secp256k1.PubKey{Key: pubKeyBytes}
	pubKeyAny, err := codectypes.NewAnyWithValue(cosmosPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create pubkey any: %w", err)
	}

	// Create fee
	feeAmount, ok := math.NewIntFromString(cosmosFeeAmount)
	if !ok {
		return nil, nil, fmt.Errorf("invalid fee amount")
	}
	fee := &tx.Fee{
		Amount:   cosmostypes.NewCoins(cosmostypes.NewCoin(cosmosAtomDenom, feeAmount)),
		GasLimit: cosmosGasLimit,
	}

	// Create signer info
	signerInfo := &tx.SignerInfo{
		PublicKey: pubKeyAny,
		ModeInfo: &tx.ModeInfo{
			Sum: &tx.ModeInfo_Single_{
				Single: &tx.ModeInfo_Single{
					Mode: signing.SignMode_SIGN_MODE_DIRECT,
				},
			},
		},
		Sequence: sequence,
	}

	// Create auth info
	authInfo := &tx.AuthInfo{
		SignerInfos: []*tx.SignerInfo{signerInfo},
		Fee:         fee,
	}

	// Create tx body with memo
	txBody := &tx.TxBody{
		Messages: []*codectypes.Any{msgAny},
		Memo:     memo,
	}

	// Marshal body and auth info
	bodyBytes, err := p.cdc.Marshal(txBody)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal tx body: %w", err)
	}

	authInfoBytes, err := p.cdc.Marshal(authInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal auth info: %w", err)
	}

	// Create sign doc
	signDoc := &tx.SignDoc{
		BodyBytes:     bodyBytes,
		AuthInfoBytes: authInfoBytes,
		ChainId:       cosmosChainID,
		AccountNumber: accountNumber,
	}

	signBytes, err := signDoc.Marshal()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal sign doc: %w", err)
	}

	// Create unsigned transaction
	unsignedTx := &tx.Tx{
		Body:       txBody,
		AuthInfo:   authInfo,
		Signatures: [][]byte{{}},
	}

	txBytes, err := p.cdc.Marshal(unsignedTx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal tx: %w", err)
	}

	return txBytes, signBytes, nil
}

