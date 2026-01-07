package rune

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	cosmosSdk "github.com/vultisig/recipes/sdk/cosmos"
	"github.com/vultisig/verifier/plugin/keysign"
	"github.com/vultisig/verifier/plugin/tx_indexer"
	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/storage"
	"github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/common"
)

// SignerService handles signing and broadcasting THORChain transactions
type SignerService struct {
	sdk       *cosmosSdk.SDK
	signer    *keysign.Signer
	txIndexer *tx_indexer.Service
}

// NewSignerService creates a new SignerService
func NewSignerService(
	sdk *cosmosSdk.SDK,
	signer *keysign.Signer,
	txIndexer *tx_indexer.Service,
) *SignerService {
	return &SignerService{
		sdk:       sdk,
		signer:    signer,
		txIndexer: txIndexer,
	}
}

// SignAndBroadcast signs the transaction and broadcasts it
func (s *SignerService) SignAndBroadcast(
	ctx context.Context,
	policy types.PluginPolicy,
	txData []byte,
	signBytes []byte,
	pubKey []byte,
) (string, error) {
	keysignRequest, err := s.buildKeysignRequest(ctx, policy, txData, signBytes)
	if err != nil {
		return "", fmt.Errorf("rune: failed to build keysign request: %w", err)
	}

	signatures, err := s.signer.Sign(ctx, keysignRequest)
	if err != nil {
		return "", fmt.Errorf("rune: failed to get signature: %w", err)
	}

	signedTxBytes, err := s.sdk.Sign(txData, signatures, pubKey)
	if err != nil {
		return "", fmt.Errorf("rune: failed to sign transaction: %w", err)
	}

	_, err = s.sdk.Broadcast(ctx, signedTxBytes)
	if err != nil {
		return "", fmt.Errorf("rune: failed to broadcast transaction: %w", err)
	}

	// THORChain txHash is SHA256 of signed tx bytes (uppercase hex)
	txHash := s.sdk.ComputeTxHash(signedTxBytes)

	return txHash, nil
}

func (s *SignerService) buildKeysignRequest(
	ctx context.Context,
	policy types.PluginPolicy,
	txData []byte,
	signBytes []byte,
) (types.PluginKeysignRequest, error) {
	// For Cosmos-based chains, the hash to sign is SHA256 of the sign bytes
	hashToSign := sha256.Sum256(signBytes)

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
		return types.PluginKeysignRequest{}, fmt.Errorf("rune: failed to create tx: %w", err)
	}

	// Create keysign message
	hashToSignBase64 := base64.StdEncoding.EncodeToString(hashToSign[:])
	hashHex := hex.EncodeToString(hashToSign[:])

	msg := types.KeysignMessage{
		TxIndexerID:  txToTrack.ID.String(),
		Message:      hashToSignBase64,
		Hash:         hashHex,
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
