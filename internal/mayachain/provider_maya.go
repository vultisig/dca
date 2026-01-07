package mayachain

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"

	"cosmossdk.io/math"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cosmostypes "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"

	maya_swap "github.com/vultisig/dca/internal/maya"
	"github.com/vultisig/recipes/sdk/swap"
	"github.com/vultisig/vultisig-go/common"
)

const (
	mayaGasLimit  = uint64(4000000000)
	mayaFeeAmount = "2000000000"
	mayaChainID   = "mayachain-mainnet-v1"
	cacaoDenom    = "cacao"
)

type ProviderMaya struct {
	cdc codec.Codec
}

func NewProviderMaya(_ *Client) *ProviderMaya {
	ir := codectypes.NewInterfaceRegistry()
	cryptocodec.RegisterInterfaces(ir)
	banktypes.RegisterInterfaces(ir)

	return &ProviderMaya{
		cdc: codec.NewProtoCodec(ir),
	}
}

func (p *ProviderMaya) MakeTransaction(
	ctx context.Context,
	from maya_swap.From,
	to maya_swap.To,
) (txData []byte, signBytes []byte, toAmount uint64, err error) {
	if to.Chain == common.MayaChain && to.AssetID == from.AssetID {
		return nil, nil, 0, fmt.Errorf("[MAYA] can't swap same asset to same asset")
	}

	_, err = parseMayaNetwork(to.Chain)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("[MAYA] unsupported destination chain: %w", err)
	}

	fromAsset := swap.NativeAsset("MayaChain", "CACAO", 10)
	toAsset := p.buildToAsset(to)

	quote, err := swap.GetQuote(ctx, swap.QuoteRequest{
		From:        fromAsset,
		To:          toAsset,
		Amount:      new(big.Int).SetUint64(from.Amount),
		Sender:      from.Address,
		Destination: to.Address,
	})
	if err != nil {
		return nil, nil, 0, fmt.Errorf("[MAYA] failed to get quote: %w", err)
	}

	if quote.Provider != "Mayachain" {
		return nil, nil, 0, fmt.Errorf("[MAYA] unexpected provider: %s (expected Mayachain)", quote.Provider)
	}

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
		return nil, nil, 0, fmt.Errorf("[MAYA] failed to build transaction: %w", err)
	}

	expectedOut := quote.ExpectedOutput.Uint64()

	return txData, signBytes, expectedOut, nil
}

func (p *ProviderMaya) buildToAsset(to maya_swap.To) swap.Asset {
	symbol, _ := to.Chain.NativeSymbol()

	if to.AssetID == "" {
		decimals := 8
		switch to.Chain {
		case common.Ethereum, common.Arbitrum:
			decimals = 18
		case common.THORChain:
			decimals = 8
		}
		return swap.NativeAsset(to.Chain.String(), symbol, decimals)
	}

	return swap.NewAsset(to.Chain.String(), symbol, to.AssetID, 18)
}

func (p *ProviderMaya) buildDepositTransaction(
	from string,
	inboundAddress string,
	amountCacao uint64,
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

	coins := cosmostypes.NewCoins(cosmostypes.NewCoin(cacaoDenom, math.NewIntFromUint64(amountCacao)))
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

	feeAmount, ok := math.NewIntFromString(mayaFeeAmount)
	if !ok {
		return nil, nil, fmt.Errorf("invalid fee amount")
	}
	fee := &tx.Fee{
		Amount:   cosmostypes.NewCoins(cosmostypes.NewCoin(cacaoDenom, feeAmount)),
		GasLimit: mayaGasLimit,
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
		ChainId:       mayaChainID,
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
