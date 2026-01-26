package tron

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/sirupsen/logrus"
	tronSdk "github.com/vultisig/recipes/sdk/tron"
	"github.com/vultisig/verifier/plugin/keysign"
	"github.com/vultisig/verifier/plugin/tx_indexer"
	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/storage"
	"github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/common"
)

// SignerService handles TRON transaction signing and broadcasting
type SignerService struct {
	sdk       *tronSdk.SDK
	signer    *keysign.Signer
	txIndexer *tx_indexer.Service
}

// NewSignerService creates a new SignerService
func NewSignerService(
	sdk *tronSdk.SDK,
	signer *keysign.Signer,
	txIndexer *tx_indexer.Service,
) *SignerService {
	return &SignerService{
		sdk:       sdk,
		signer:    signer,
		txIndexer: txIndexer,
	}
}

// SignAndBroadcast signs a TRON transaction and broadcasts it
func (s *SignerService) SignAndBroadcast(
	ctx context.Context,
	policy types.PluginPolicy,
	txData []byte,
	pubKey []byte,
) (string, error) {
	previewLen := len(txData)
	if previewLen > 100 {
		previewLen = 100
	}
	logrus.WithFields(logrus.Fields{
		"txDataLen": len(txData),
		"preview":   hex.EncodeToString(txData[:previewLen]),
	}).Debug("tron: SignAndBroadcast called")

	keysignRequest, err := s.buildKeysignRequest(ctx, policy, txData)
	if err != nil {
		return "", fmt.Errorf("tron: failed to build keysign request: %w", err)
	}

	logrus.WithField("transactionLen", len(keysignRequest.Transaction)).Debug("tron: keysign request built")

	signatures, err := s.signer.Sign(ctx, keysignRequest)
	if err != nil {
		return "", fmt.Errorf("tron: failed to get signature: %w", err)
	}

	signedTxBytes, err := s.sdk.Sign(txData, signatures, pubKey)
	if err != nil {
		return "", fmt.Errorf("tron: failed to sign transaction: %w", err)
	}

	_, err = s.sdk.Broadcast(ctx, signedTxBytes)
	if err != nil {
		return "", fmt.Errorf("tron: failed to broadcast transaction: %w", err)
	}

	// TRON txID is SHA256 of raw_data
	txHash := s.sdk.ComputeTxHash(txData)

	return txHash, nil
}

func (s *SignerService) buildKeysignRequest(
	ctx context.Context,
	policy types.PluginPolicy,
	txData []byte,
) (types.PluginKeysignRequest, error) {
	// For TRON, the hash to sign is SHA256 of the raw_data bytes
	hashToSign := sha256.Sum256(txData)

	// Create tx tracking entry
	txBase64 := base64.StdEncoding.EncodeToString(txData)
	txToTrack, err := s.txIndexer.CreateTx(ctx, storage.CreateTxDto{
		PluginID:      policy.PluginID,
		PolicyID:      policy.ID,
		ChainID:       common.Tron,
		TokenID:       "",
		FromPublicKey: policy.PublicKey,
		ToPublicKey:   "",
		ProposedTxHex: txBase64,
	})
	if err != nil {
		return types.PluginKeysignRequest{}, fmt.Errorf("tron: failed to create tx: %w", err)
	}

	// Create keysign message
	hashToSignBase64 := base64.StdEncoding.EncodeToString(hashToSign[:])
	hashHex := hex.EncodeToString(hashToSign[:])

	msg := types.KeysignMessage{
		TxIndexerID:  txToTrack.ID.String(),
		Message:      hashToSignBase64,
		Hash:         hashHex,
		HashFunction: types.HashFunction_SHA256,
		Chain:        common.Tron,
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

