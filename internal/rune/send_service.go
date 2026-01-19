package rune

import (
	"context"
	"encoding/hex"
	"fmt"

	"cosmossdk.io/math"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cosmostypes "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
)

const (
	// DefaultGasLimit for THORChain transactions
	DefaultGasLimit = uint64(4000000000)
	// DefaultFeeAmount in rune base units
	DefaultFeeAmount = "2000000"
	// THORChainID is the chain ID for THORChain mainnet
	THORChainID = "thorchain-1"
	// RuneDenom is the denomination for RUNE
	RuneDenom = "rune"
	// ThorBech32HRP is the Bech32 human-readable prefix for THORChain addresses
	ThorBech32HRP = "thor"
)

// SendService handles building THORChain send transactions
type SendService struct {
	client  AccountInfoProvider
	chainID string
	cdc     codec.Codec
}

// NewSendService creates a new SendService
func NewSendService(client AccountInfoProvider, chainID string) *SendService {
	ir := codectypes.NewInterfaceRegistry()
	cryptocodec.RegisterInterfaces(ir)
	banktypes.RegisterInterfaces(ir)

	return &SendService{
		client:  client,
		chainID: chainID,
		cdc:     codec.NewProtoCodec(ir),
	}
}

// BuildTransfer builds an unsigned THORChain bank send transaction
// Returns the transaction bytes and the sign bytes for TSS signing
func (s *SendService) BuildTransfer(
	ctx context.Context,
	from string,
	to string,
	amountRune uint64,
	pubKeyHex string,
) ([]byte, []byte, error) {
	// Get account info for sequence and account number
	accountInfo, err := s.client.GetAccount(ctx, from)
	if err != nil {
		return nil, nil, fmt.Errorf("rune: failed to get account info: %w", err)
	}

	return s.BuildTransferWithAccountInfo(
		ctx,
		from,
		to,
		amountRune,
		pubKeyHex,
		accountInfo.AccountNumber,
		accountInfo.Sequence,
	)
}

// BuildTransferWithAccountInfo builds an unsigned THORChain bank send transaction with explicit account info
func (s *SendService) BuildTransferWithAccountInfo(
	ctx context.Context,
	from string,
	to string,
	amountRune uint64,
	pubKeyHex string,
	accountNumber uint64,
	sequence uint64,
) ([]byte, []byte, error) {
	// Parse addresses (THORChain uses "thor" prefix)
	fromAddr, err := cosmostypes.AccAddressFromBech32(from)
	if err != nil {
		return nil, nil, fmt.Errorf("rune: invalid from address: %w", err)
	}

	toAddr, err := cosmostypes.AccAddressFromBech32(to)
	if err != nil {
		return nil, nil, fmt.Errorf("rune: invalid to address: %w", err)
	}

	// Create send message
	amount := cosmostypes.NewCoins(cosmostypes.NewCoin(RuneDenom, math.NewIntFromUint64(amountRune)))
	sendMsg := banktypes.NewMsgSend(fromAddr, toAddr, amount)

	// Wrap message in Any
	msgAny, err := codectypes.NewAnyWithValue(sendMsg)
	if err != nil {
		return nil, nil, fmt.Errorf("rune: failed to create message any: %w", err)
	}

	// Decode public key
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, nil, fmt.Errorf("rune: failed to decode pubkey: %w", err)
	}

	if len(pubKeyBytes) != 33 {
		return nil, nil, fmt.Errorf("rune: invalid pubkey length: expected 33 bytes, got %d", len(pubKeyBytes))
	}

	// Create Cosmos public key
	cosmosPubKey := &secp256k1.PubKey{Key: pubKeyBytes}
	pubKeyAny, err := codectypes.NewAnyWithValue(cosmosPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("rune: failed to create pubkey any: %w", err)
	}

	// Create fee
	feeAmount, ok := math.NewIntFromString(DefaultFeeAmount)
	if !ok {
		return nil, nil, fmt.Errorf("rune: invalid fee amount")
	}
	fee := &tx.Fee{
		Amount:   cosmostypes.NewCoins(cosmostypes.NewCoin(RuneDenom, feeAmount)),
		GasLimit: DefaultGasLimit,
	}

	// Create signer info (empty signature for unsigned tx)
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

	// Create tx body
	txBody := &tx.TxBody{
		Messages: []*codectypes.Any{msgAny},
		Memo:     "",
	}

	// Marshal body and auth info
	bodyBytes, err := s.cdc.Marshal(txBody)
	if err != nil {
		return nil, nil, fmt.Errorf("rune: failed to marshal tx body: %w", err)
	}

	authInfoBytes, err := s.cdc.Marshal(authInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("rune: failed to marshal auth info: %w", err)
	}

	// Create sign doc
	signDoc := &tx.SignDoc{
		BodyBytes:     bodyBytes,
		AuthInfoBytes: authInfoBytes,
		ChainId:       s.chainID,
		AccountNumber: accountNumber,
	}

	signBytes, err := signDoc.Marshal()
	if err != nil {
		return nil, nil, fmt.Errorf("rune: failed to marshal sign doc: %w", err)
	}

	// Create unsigned transaction
	unsignedTx := &tx.Tx{
		Body:       txBody,
		AuthInfo:   authInfo,
		Signatures: [][]byte{{}}, // Empty signature placeholder
	}

	txBytes, err := s.cdc.Marshal(unsignedTx)
	if err != nil {
		return nil, nil, fmt.Errorf("rune: failed to marshal tx: %w", err)
	}

	return txBytes, signBytes, nil
}

// GetSequence fetches the current account sequence number
func (s *SendService) GetSequence(ctx context.Context, address string) (uint64, error) {
	accountInfo, err := s.client.GetAccount(ctx, address)
	if err != nil {
		return 0, fmt.Errorf("rune: failed to get account: %w", err)
	}
	return accountInfo.Sequence, nil
}

