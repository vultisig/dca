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

	"github.com/vultisig/app-recurring/internal/mayachain"
	rune_swap "github.com/vultisig/app-recurring/internal/rune"
	thorchaintypes "github.com/vultisig/recipes/types"
	"github.com/vultisig/vultisig-go/common"
)

const (
	runeGasLimit  = uint64(4000000000)
	runeFeeAmount = "2000000"
	runeChainID   = "thorchain-1"
	runeDenom     = "rune"
)

// ProviderRune implements the rune.SwapProvider interface for THORChain swaps from RUNE
// with Maya fallback for chains not supported by THORChain (ARB, ZEC, DASH)
type ProviderRune struct {
	thorClient *Client
	mayaClient *mayachain.Client
	cdc        codec.Codec
}

// NewProviderRune creates a new THORChain provider for RUNE swaps with Maya fallback
func NewProviderRune(thorClient *Client, mayaClient *mayachain.Client) *ProviderRune {
	ir := codectypes.NewInterfaceRegistry()
	cryptocodec.RegisterInterfaces(ir)
	banktypes.RegisterInterfaces(ir)

	return &ProviderRune{
		thorClient: thorClient,
		mayaClient: mayaClient,
		cdc:        codec.NewProtoCodec(ir),
	}
}

// MakeTransaction builds a THORChain transaction for a swap from RUNE
// It tries THORChain first, then falls back to Maya for unsupported chains (ARB, ZEC, DASH)
func (p *ProviderRune) MakeTransaction(
	ctx context.Context,
	from rune_swap.From,
	to rune_swap.To,
) (txData []byte, signBytes []byte, toAmount uint64, err error) {
	if to.Chain == common.THORChain && to.AssetID == from.AssetID {
		return nil, nil, 0, fmt.Errorf("[RUNE] can't swap same asset to same asset")
	}

	_, thorErr := parseThorNetwork(to.Chain)
	if thorErr == nil {
		txData, signBytes, toAmount, err = p.makeTransactionViaThorchain(ctx, from, to)
		if err == nil {
			return txData, signBytes, toAmount, nil
		}
	}

	if p.mayaClient != nil {
		txData, signBytes, toAmount, err = p.makeTransactionViaMaya(ctx, from, to)
		if err == nil {
			return txData, signBytes, toAmount, nil
		}
		return nil, nil, 0, fmt.Errorf("[RUNE] THORChain failed: %v, Maya fallback also failed: %w", thorErr, err)
	}

	if thorErr != nil {
		return nil, nil, 0, fmt.Errorf("[RUNE] unsupported destination chain: %w", thorErr)
	}
	return nil, nil, 0, fmt.Errorf("[RUNE] failed to get quote: %w", err)
}

func (p *ProviderRune) makeTransactionViaThorchain(
	ctx context.Context,
	from rune_swap.From,
	to rune_swap.To,
) (txData []byte, signBytes []byte, toAmount uint64, err error) {
	fromAsset := "THOR.RUNE"

	toAsset, err := makeThorAsset(ctx, p.thorClient, to.Chain, to.AssetID)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to resolve to asset: %w", err)
	}

	thorAmount := from.Amount

	quote, err := p.thorClient.getQuote(ctx, quoteSwapRequest{
		FromAsset:         fromAsset,
		ToAsset:           toAsset,
		Amount:            strconv.FormatUint(thorAmount, 10),
		Destination:       to.Address,
		StreamingInterval: defaultStreamingInterval,
		StreamingQuantity: defaultStreamingQuantity,
		ToleranceBps:      defaultToleranceBps,
	})
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to get quote: %w", err)
	}

	dustThreshold, err := strconv.ParseUint(quote.DustThreshold, 10, 64)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to parse dust threshold: %w", err)
	}

	if thorAmount < dustThreshold {
		return nil, nil, 0, fmt.Errorf("amount %d below dust threshold %d", thorAmount, dustThreshold)
	}

	txData, signBytes, err = p.buildMsgDepositTransaction(
		from.Address,
		from.Amount,
		from.PubKey,
		from.AccountNumber,
		from.Sequence,
		quote.Memo,
	)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to build transaction: %w", err)
	}

	expectedOut, err := strconv.ParseUint(quote.ExpectedAmountOut, 10, 64)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to parse expected amount out: %w", err)
	}

	return txData, signBytes, expectedOut, nil
}

func (p *ProviderRune) makeTransactionViaMaya(
	ctx context.Context,
	from rune_swap.From,
	to rune_swap.To,
) (txData []byte, signBytes []byte, toAmount uint64, err error) {
	fromAsset := "THOR.RUNE"

	toAsset, err := mayachain.MakeMayaAsset(ctx, p.mayaClient, to.Chain, to.AssetID)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to resolve to asset: %w", err)
	}

	quote, err := p.mayaClient.GetQuote(ctx, mayachain.QuoteSwapRequest{
		FromAsset:         fromAsset,
		ToAsset:           toAsset,
		Amount:            strconv.FormatUint(from.Amount, 10),
		Destination:       to.Address,
		StreamingInterval: mayachain.DefaultStreamingInterval,
		StreamingQuantity: mayachain.DefaultStreamingQuantity,
	})
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to get maya quote: %w", err)
	}

	dustThreshold, err := strconv.ParseUint(quote.DustThreshold, 10, 64)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to parse dust threshold: %w", err)
	}

	if from.Amount < dustThreshold {
		return nil, nil, 0, fmt.Errorf("amount %d below dust threshold %d", from.Amount, dustThreshold)
	}

	txData, signBytes, err = p.buildMsgSendTransaction(
		from.Address,
		quote.InboundAddress,
		from.Amount,
		from.PubKey,
		from.AccountNumber,
		from.Sequence,
		quote.Memo,
	)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to build maya transaction: %w", err)
	}

	expectedOut, err := strconv.ParseUint(quote.ExpectedAmountOut, 10, 64)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to parse expected amount out: %w", err)
	}

	return txData, signBytes, expectedOut, nil
}

// buildMsgDepositTransaction builds a THORChain MsgDeposit transaction for native RUNE swaps
func (p *ProviderRune) buildMsgDepositTransaction(
	from string,
	amountRune uint64,
	pubKeyHex string,
	accountNumber uint64,
	sequence uint64,
	memo string,
) ([]byte, []byte, error) {
	fromAddr, err := cosmostypes.AccAddressFromBech32(from)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid from address: %w", err)
	}

	msgDeposit := &thorchaintypes.MsgDeposit{
		Coins: []*thorchaintypes.Coin{{
			Asset: &thorchaintypes.Asset{
				Chain:  "THOR",
				Symbol: "RUNE",
				Ticker: "RUNE",
			},
			Amount:   strconv.FormatUint(amountRune, 10),
			Decimals: 8,
		}},
		Memo:   memo,
		Signer: fromAddr.Bytes(),
	}

	msgAny, err := codectypes.NewAnyWithValue(msgDeposit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create message any: %w", err)
	}

	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode pubkey: %w", err)
	}

	if len(pubKeyBytes) != 33 {
		return nil, nil, fmt.Errorf("invalid pubkey length: expected 33 bytes, got %d", len(pubKeyBytes))
	}

	cosmosPubKey := &secp256k1.PubKey{Key: pubKeyBytes}
	pubKeyAny, err := codectypes.NewAnyWithValue(cosmosPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create pubkey any: %w", err)
	}

	feeAmount, ok := math.NewIntFromString(runeFeeAmount)
	if !ok {
		return nil, nil, fmt.Errorf("invalid fee amount")
	}
	fee := &tx.Fee{
		Amount:   cosmostypes.NewCoins(cosmostypes.NewCoin(runeDenom, feeAmount)),
		GasLimit: runeGasLimit,
	}

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

	authInfo := &tx.AuthInfo{
		SignerInfos: []*tx.SignerInfo{signerInfo},
		Fee:         fee,
	}

	txBody := &tx.TxBody{
		Messages: []*codectypes.Any{msgAny},
		Memo:     "",
	}

	bodyBytes, err := p.cdc.Marshal(txBody)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal tx body: %w", err)
	}

	authInfoBytes, err := p.cdc.Marshal(authInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal auth info: %w", err)
	}

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

// buildMsgSendTransaction builds a MsgSend transaction for Maya swaps
// Maya swaps are initiated by sending RUNE to Maya's inbound address with a memo
func (p *ProviderRune) buildMsgSendTransaction(
	from string,
	inboundAddress string,
	amountRune uint64,
	pubKeyHex string,
	accountNumber uint64,
	sequence uint64,
	memo string,
) ([]byte, []byte, error) {
	fromAddr, err := cosmostypes.AccAddressFromBech32(from)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid from address: %w", err)
	}

	toAddr, err := cosmostypes.AccAddressFromBech32(inboundAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid inbound address: %w", err)
	}

	coins := cosmostypes.NewCoins(cosmostypes.NewCoin(runeDenom, math.NewIntFromUint64(amountRune)))
	sendMsg := banktypes.NewMsgSend(fromAddr, toAddr, coins)

	msgAny, err := codectypes.NewAnyWithValue(sendMsg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create message any: %w", err)
	}

	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode pubkey: %w", err)
	}

	if len(pubKeyBytes) != 33 {
		return nil, nil, fmt.Errorf("invalid pubkey length: expected 33 bytes, got %d", len(pubKeyBytes))
	}

	cosmosPubKey := &secp256k1.PubKey{Key: pubKeyBytes}
	pubKeyAny, err := codectypes.NewAnyWithValue(cosmosPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create pubkey any: %w", err)
	}

	feeAmount, ok := math.NewIntFromString(runeFeeAmount)
	if !ok {
		return nil, nil, fmt.Errorf("invalid fee amount")
	}
	fee := &tx.Fee{
		Amount:   cosmostypes.NewCoins(cosmostypes.NewCoin(runeDenom, feeAmount)),
		GasLimit: runeGasLimit,
	}

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

	authInfo := &tx.AuthInfo{
		SignerInfos: []*tx.SignerInfo{signerInfo},
		Fee:         fee,
	}

	txBody := &tx.TxBody{
		Messages: []*codectypes.Any{msgAny},
		Memo:     memo,
	}

	bodyBytes, err := p.cdc.Marshal(txBody)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal tx body: %w", err)
	}

	authInfoBytes, err := p.cdc.Marshal(authInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal auth info: %w", err)
	}

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

