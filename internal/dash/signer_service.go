package dash

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/vultisig/recipes/sdk/btc"
	"github.com/vultisig/verifier/plugin/keysign"
	"github.com/vultisig/verifier/plugin/tx_indexer"
	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/storage"
	"github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/common"
)

// SignerService handles signing and broadcasting Dash transactions
type SignerService struct {
	sdk       *btc.SDK
	signer    *keysign.Signer
	txIndexer *tx_indexer.Service
}

// NewSignerService creates a new SignerService
func NewSignerService(
	sdk *btc.SDK,
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
	psbtUnsigned []byte,
) (string, error) {
	keysignRequest, err := s.buildKeysignRequest(ctx, policy, psbtUnsigned)
	if err != nil {
		return "", fmt.Errorf("dash: failed to build keysign request: %w", err)
	}

	signatures, err := s.signer.Sign(ctx, keysignRequest)
	if err != nil {
		return "", fmt.Errorf("dash: failed to get TSS signatures: %w", err)
	}

	signedTx, err := s.sdk.Sign(psbtUnsigned, signatures)
	if err != nil {
		return "", fmt.Errorf("dash: failed to apply signatures to PSBT: %w", err)
	}

	err = s.sdk.Broadcast(signedTx)
	if err != nil {
		return "", fmt.Errorf("dash: failed to broadcast transaction: %w", err)
	}

	tx := wire.NewMsgTx(wire.TxVersion)
	err = tx.Deserialize(bytes.NewReader(signedTx))
	if err != nil {
		return "", fmt.Errorf("dash: failed to deserialize transaction: %w", err)
	}

	return tx.TxID(), nil
}

func (s *SignerService) buildKeysignRequest(
	ctx context.Context,
	policy types.PluginPolicy,
	psbtUnsigned []byte,
) (types.PluginKeysignRequest, error) {
	tx, err := psbt.NewFromRawBytes(bytes.NewReader(psbtUnsigned), false)
	if err != nil {
		return types.PluginKeysignRequest{}, fmt.Errorf("dash: failed to make psbt: %w", err)
	}

	txB64, err := tx.B64Encode()
	if err != nil {
		return types.PluginKeysignRequest{}, fmt.Errorf("dash: failed to encode psbt: %w", err)
	}

	txToTrack, err := s.txIndexer.CreateTx(ctx, storage.CreateTxDto{
		PluginID:      policy.PluginID,
		PolicyID:      policy.ID,
		ChainID:       common.Dash,
		TokenID:       "",
		FromPublicKey: policy.PublicKey,
		ToPublicKey:   "",
		ProposedTxHex: txB64,
	})
	if err != nil {
		return types.PluginKeysignRequest{}, fmt.Errorf("dash: failed to create tx: %w", err)
	}

	var msgs []types.KeysignMessage
	for i := range tx.Inputs {
		hashToSign, er := s.sdk.CalculateInputSignatureHash(tx, i)
		if er != nil {
			return types.PluginKeysignRequest{}, fmt.Errorf("dash: failed to calculate input signature hash: %w", er)
		}

		msgHash := sha256.Sum256(hashToSign)
		msgs = append(msgs, types.KeysignMessage{
			TxIndexerID:  txToTrack.ID.String(),
			Message:      base64.StdEncoding.EncodeToString(hashToSign),
			Hash:         base64.StdEncoding.EncodeToString(msgHash[:]),
			HashFunction: types.HashFunction_SHA256,
			Chain:        common.Dash,
		})
	}

	return types.PluginKeysignRequest{
		KeysignRequest: types.KeysignRequest{
			PublicKey: policy.PublicKey,
			Messages:  msgs,
			PolicyID:  policy.ID,
			PluginID:  policy.PluginID.String(),
		},
		Transaction: txB64,
	}, nil
}
