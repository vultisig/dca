package thorchain_native

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/vultisig/mobile-tss-lib/tss"
	"github.com/vultisig/verifier/plugin/keysign"
	"github.com/vultisig/verifier/plugin/tx_indexer"
	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/storage"
	"github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/common"
)

type SignerService struct {
	sdk       ThorchainSDK // THORChain Cosmos SDK wrapper interface
	signer    *keysign.Signer
	txIndexer *tx_indexer.Service
}

// ThorchainSDK interface for THORChain Cosmos SDK operations
type ThorchainSDK interface {
	Sign(txData []byte, signatures map[string]tss.KeysignResponse) ([]byte, error)
	Broadcast(ctx context.Context, signedTxBytes []byte) error
}

func NewSignerService(
	sdk ThorchainSDK,
	signer *keysign.Signer,
	txIndexer *tx_indexer.Service,
) *SignerService {
	return &SignerService{
		sdk:       sdk,
		signer:    signer,
		txIndexer: txIndexer,
	}
}

func (s *SignerService) SignAndBroadcast(
	ctx context.Context,
	policy types.PluginPolicy,
	txData []byte,
) (string, error) {
	// TODO: Implement proper THORChain signing and broadcasting
	// This requires the THORChain SDK from recipes to be available
	if s.sdk == nil {
		return "", fmt.Errorf("thorchain: SDK not available - THORChain signing not yet implemented")
	}

	keysignRequest, err := s.buildKeysignRequest(ctx, policy, txData)
	if err != nil {
		return "", fmt.Errorf("thorchain: failed to build keysign request: %w", err)
	}

	signatures, err := s.signer.Sign(ctx, keysignRequest)
	if err != nil {
		return "", fmt.Errorf("thorchain: failed to get signature: %w", err)
	}

	// Sign the transaction using THORChain SDK
	// The SDK handles public key extraction internally from the transaction
	signedTxBytes, err := s.sdk.Sign(txData, signatures)
	if err != nil {
		return "", fmt.Errorf("thorchain: failed to sign transaction: %w", err)
	}

	err = s.sdk.Broadcast(ctx, signedTxBytes)
	if err != nil {
		return "", fmt.Errorf("thorchain: failed to broadcast transaction: %w", err)
	}

	// Extract transaction hash from signed transaction
	txHash, err := s.extractTransactionHash(signedTxBytes)
	if err != nil {
		return "", fmt.Errorf("thorchain: failed to extract transaction hash: %w", err)
	}

	return txHash, nil
}

func (s *SignerService) buildKeysignRequest(
	ctx context.Context,
	policy types.PluginPolicy,
	txData []byte,
) (types.PluginKeysignRequest, error) {
	// Calculate hash-to-sign for THORChain Cosmos SDK transaction
	hashToSign, err := s.calculateCosmosHashToSign(txData)
	if err != nil {
		return types.PluginKeysignRequest{}, fmt.Errorf("thorchain: failed to calculate hash to sign: %w", err)
	}

	// Create tx tracking entry
	txBase64 := base64.StdEncoding.EncodeToString(txData)
	txToTrack, err := s.txIndexer.CreateTx(ctx, storage.CreateTxDto{
		PluginID:      policy.PluginID,
		PolicyID:      policy.ID,
		ChainID:       common.THORChain,
		TokenID:       "",
		FromPublicKey: policy.PublicKey,
		ToPublicKey:   "",
		ProposedTxHex: txBase64,
	})
	if err != nil {
		return types.PluginKeysignRequest{}, fmt.Errorf("thorchain: failed to create tx: %w", err)
	}

	// Create keysign message - THORChain uses standard Cosmos SDK signing
	hashToSignBase64 := base64.StdEncoding.EncodeToString(hashToSign)

	msg := types.KeysignMessage{
		TxIndexerID:  txToTrack.ID.String(),
		Message:      hashToSignBase64,
		Hash:         hashToSignBase64,
		HashFunction: types.HashFunction_SHA256,
		Chain:        common.THORChain,
	}

	return types.PluginKeysignRequest{
		KeysignRequest: types.KeysignRequest{
			PublicKey: policy.PublicKey,
			Messages:  []types.KeysignMessage{msg},
			PolicyID:  policy.ID,
			PluginID:  policy.PluginID.String(),
		},
		Transaction: txBase64,
	}, nil
}

func (s *SignerService) calculateCosmosHashToSign(txData []byte) ([]byte, error) {
	// For Cosmos SDK transactions, the hash to sign is typically:
	// SHA256(sign_doc) where sign_doc contains the transaction data
	// This is a simplified implementation - real Cosmos SDK signing is more complex
	
	hash := sha256.Sum256(txData)
	return hash[:], nil
}


func (s *SignerService) extractTransactionHash(signedTxBytes []byte) (string, error) {
	// For Cosmos SDK transactions, the transaction hash is typically:
	// SHA256(signed_transaction_bytes)
	
	hash := sha256.Sum256(signedTxBytes)
	txHash := hex.EncodeToString(hash[:])
	
	return strings.ToUpper(txHash), nil
}