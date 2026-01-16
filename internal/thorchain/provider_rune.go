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

	rune_swap "github.com/vultisig/app-recurring/internal/rune"
	"github.com/vultisig/vultisig-go/common"
)

const (
	runeGasLimit  = uint64(4000000000)
	runeFeeAmount = "2000000"
	runeChainID   = "thorchain-1"
	runeDenom     = "rune"
)

// ProviderRune implements the rune.SwapProvider interface for THORChain swaps from RUNE
type ProviderRune struct {
	client *Client
	cdc    codec.Codec
}

// NewProviderRune creates a new THORChain provider for RUNE swaps
func NewProviderRune(client *Client) *ProviderRune {
	ir := codectypes.NewInterfaceRegistry()
	cryptocodec.RegisterInterfaces(ir)
	banktypes.RegisterInterfaces(ir)

	return &ProviderRune{
		client: client,
		cdc:    codec.NewProtoCodec(ir),
	}
}

// MakeTransaction builds a THORChain transaction for a swap from RUNE
func (p *ProviderRune) MakeTransaction(
	ctx context.Context,
	from rune_swap.From,
	to rune_swap.To,
) (txData []byte, signBytes []byte, toAmount uint64, err error) {
	// Validate source and destination
	if to.Chain == common.THORChain && to.AssetID == from.AssetID {
		return nil, nil, 0, fmt.Errorf("[RUNE] can't swap same asset to same asset")
	}

	// Validate that the destination chain is supported by THORChain
	_, err = parseThorNetwork(to.Chain)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("[RUNE] unsupported destination chain: %w", err)
	}

	// Build the from asset string (THOR.RUNE for native)
	fromAsset := "THOR.RUNE"

	// Build the to asset string
	toAsset, err := makeThorAsset(ctx, p.client, to.Chain, to.AssetID)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("[RUNE] failed to resolve to asset: %w", err)
	}

	// RUNE uses 8 decimals, same as THORChain internal
	thorAmount := from.Amount

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
		return nil, nil, 0, fmt.Errorf("[RUNE] failed to get quote: %w", err)
	}

	// Check dust threshold
	dustThreshold, err := strconv.ParseUint(quote.DustThreshold, 10, 64)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("[RUNE] failed to parse dust threshold: %w", err)
	}

	if thorAmount < dustThreshold {
		return nil, nil, 0, fmt.Errorf("[RUNE] amount %d below dust threshold %d", thorAmount, dustThreshold)
	}

	// Build the THORChain deposit transaction with memo
	txData, signBytes, err = p.buildDepositTransaction(
		from.Address,
		quote.InboundAddress,
		from.Amount,
		from.PubKey,
		from.AccountNumber,
		from.Sequence,
		quote.Memo,
	)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("[RUNE] failed to build transaction: %w", err)
	}

	// Parse expected amount out
	expectedOut, err := strconv.ParseUint(quote.ExpectedAmountOut, 10, 64)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("[RUNE] failed to parse expected amount out: %w", err)
	}

	return txData, signBytes, expectedOut, nil
}

// buildDepositTransaction builds a THORChain MsgSend transaction for swaps
// THORChain swaps are initiated by sending RUNE to the THORChain module with a memo
func (p *ProviderRune) buildDepositTransaction(
	from string,
	inboundAddress string,
	amountRune uint64,
	pubKeyHex string,
	accountNumber uint64,
	sequence uint64,
	memo string,
) ([]byte, []byte, error) {
	// Parse from address (THORChain uses "thor" prefix)
	fromAddr, err := cosmostypes.AccAddressFromBech32(from)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid from address: %w", err)
	}

	// Parse inbound address (THORChain vault address)
	toAddr, err := cosmostypes.AccAddressFromBech32(inboundAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid inbound address: %w", err)
	}

	// Create send message - the memo in txBody handles the swap routing
	coins := cosmostypes.NewCoins(cosmostypes.NewCoin(runeDenom, math.NewIntFromUint64(amountRune)))
	sendMsg := banktypes.NewMsgSend(fromAddr, toAddr, coins)

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
	feeAmount, ok := math.NewIntFromString(runeFeeAmount)
	if !ok {
		return nil, nil, fmt.Errorf("invalid fee amount")
	}
	fee := &tx.Fee{
		Amount:   cosmostypes.NewCoins(cosmostypes.NewCoin(runeDenom, feeAmount)),
		GasLimit: runeGasLimit,
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

	// Create tx body with memo for swap routing
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
		ChainId:       runeChainID,
		AccountNumber: accountNumber,
	}

	signDocBytes, err := signDoc.Marshal()
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

	return txBytes, signDocBytes, nil
}

