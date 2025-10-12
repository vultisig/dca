package xrp

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/vultisig/recipes/sdk/xrpl"
	"github.com/vultisig/verifier/plugin/keysign"
	"github.com/vultisig/verifier/plugin/tx_indexer"
	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/storage"
	"github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/common"
	xrpgo "github.com/xyield/xrpl-go/binary-codec"
)

type SignerService struct {
	sdk       *xrpl.SDK
	signer    *keysign.Signer
	txIndexer *tx_indexer.Service
}

func NewSignerService(
	sdk *xrpl.SDK,
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
	keysignRequest, err := s.buildKeysignRequest(ctx, policy, txData)
	if err != nil {
		return "", fmt.Errorf("failed to build keysign request: %w", err)
	}

	signatures, err := s.signer.Sign(ctx, keysignRequest)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Get the child public key from the unsigned transaction
	pubKey, err := s.extractPublicKeyFromTx(txData)
	if err != nil {
		return "", fmt.Errorf("failed to extract public key: %w", err)
	}

	signedTxBytes, err := s.sdk.Sign(txData, signatures, pubKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	err = s.sdk.Broadcast(ctx, signedTxBytes)
	if err != nil {
		return "", fmt.Errorf("failed to broadcast transaction: %w", err)
	}

	// Extract transaction hash from signed transaction
	txHash, err := s.extractTransactionHash(signedTxBytes)
	if err != nil {
		return "", fmt.Errorf("failed to extract transaction hash: %w", err)
	}

	return txHash, nil
}

// STX prefix for XRPL transaction signing
var stxPrefix = []byte{0x53, 0x54, 0x58, 0x00} // "STX\0"

func (s *SignerService) buildKeysignRequest(
	ctx context.Context,
	policy types.PluginPolicy,
	txData []byte,
) (types.PluginKeysignRequest, error) {
	// Calculate hash-to-sign for XRPL transaction
	hashToSign, err := s.calculateXRPLHashToSign(txData)
	if err != nil {
		return types.PluginKeysignRequest{}, fmt.Errorf("failed to calculate hash to sign: %w", err)
	}

	// Create tx tracking entry
	txBase64 := base64.StdEncoding.EncodeToString(txData)
	txToTrack, err := s.txIndexer.CreateTx(ctx, storage.CreateTxDto{
		PluginID:      policy.PluginID,
		PolicyID:      policy.ID,
		ChainID:       common.XRP,
		TokenID:       "",
		FromPublicKey: policy.PublicKey,
		ToPublicKey:   "",
		ProposedTxHex: txBase64,
	})
	if err != nil {
		return types.PluginKeysignRequest{}, fmt.Errorf("failed to create tx: %w", err)
	}

	// Create keysign message - XRP uses single signature per transaction
	hashToSignBase64 := base64.StdEncoding.EncodeToString(hashToSign)

	msg := types.KeysignMessage{
		TxIndexerID:  txToTrack.ID.String(),
		Message:      hashToSignBase64,
		Hash:         hashToSignBase64,          // XRP uses hash directly
		HashFunction: types.HashFunction_SHA256, // Using SHA256 for consistency with other chains
		Chain:        common.XRP,
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

func (s *SignerService) calculateXRPLHashToSign(txData []byte) ([]byte, error) {
	// Convert to hex for binary codec processing
	baseHex := hex.EncodeToString(txData)

	// Decode the unsigned transaction
	decoded, err := xrpgo.Decode(baseHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode transaction: %w", err)
	}

	// Re-encode to get canonical bytes (with SigningPubKey but without TxnSignature)
	canonicalHex, err := xrpgo.Encode(decoded)
	if err != nil {
		return nil, fmt.Errorf("failed to encode canonical transaction: %w", err)
	}

	canonicalBytes, err := hex.DecodeString(canonicalHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode canonical hex: %w", err)
	}

	// Create XRPL signing digest: STX prefix + canonical transaction bytes
	preimage := append(stxPrefix, canonicalBytes...)

	// SHA512-half (first 32 bytes of SHA512)
	hash := sha512.Sum512(preimage)
	return hash[:32], nil
}

func (s *SignerService) extractPublicKeyFromTx(txData []byte) ([]byte, error) {
	// Convert to hex and decode transaction
	baseHex := hex.EncodeToString(txData)
	decoded, err := xrpgo.Decode(baseHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode transaction: %w", err)
	}

	// Extract SigningPubKey
	signingPubKeyHex, ok := decoded["SigningPubKey"].(string)
	if !ok {
		return nil, fmt.Errorf("SigningPubKey not found in transaction")
	}

	pubKeyBytes, err := hex.DecodeString(signingPubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SigningPubKey: %w", err)
	}

	if len(pubKeyBytes) != 33 {
		return nil, fmt.Errorf("invalid public key length: expected 33 bytes, got %d", len(pubKeyBytes))
	}

	return pubKeyBytes, nil
}

func (s *SignerService) extractTransactionHash(signedTxBytes []byte) (string, error) {
	// For XRP transaction ID computation, we need to:
	// 1. Use the fully serialized signed transaction (including TxnSignature)
	// 2. Prefix with "TXN\0" (0x54584E00)
	// 3. Hash with SHA512-half

	// XRP transaction ID prefix: "TXN\0"
	txnPrefix := []byte{0x54, 0x58, 0x4E, 0x00}

	// Construct the full preimage: TXN prefix + signed transaction bytes
	preimage := append(append([]byte{}, txnPrefix...), signedTxBytes...)

	// Compute SHA512-half (this is how XRP computes transaction IDs)
	hash := sha512.Sum512(preimage)
	txHash := hex.EncodeToString(hash[:32])

	return strings.ToUpper(txHash), nil
}
