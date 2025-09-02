package btc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

type SignerService struct {
	sdk       *btc.SDK
	signer    *keysign.Signer
	txIndexer *tx_indexer.Service
}

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

func (s *SignerService) SignAndBroadcast(
	ctx context.Context,
	policy types.PluginPolicy,
	psbtUnsigned []byte,
) (string, error) {
	keysignRequest, err := s.buildKeysignRequest(ctx, policy, psbtUnsigned)
	if err != nil {
		return "", fmt.Errorf("failed to build keysign request: %w", err)
	}

	signatures, err := s.signer.Sign(ctx, keysignRequest)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	signedTx, err := s.sdk.Sign(psbtUnsigned, signatures)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	err = s.sdk.Broadcast(signedTx)
	if err != nil {
		return "", fmt.Errorf("failed to broadcast transaction: %w", err)
	}

	tx := wire.NewMsgTx(wire.TxVersion)
	err = tx.Deserialize(bytes.NewReader(signedTx))
	if err != nil {
		return "", fmt.Errorf("failed to deserialize transaction: %w", err)
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
		return types.PluginKeysignRequest{}, fmt.Errorf("failed to make psbt: %w", err)
	}

	var txBuf bytes.Buffer
	err = tx.Serialize(&txBuf)
	if err != nil {
		return types.PluginKeysignRequest{}, fmt.Errorf("failed to serialize psbt: %w", err)
	}

	txToTrack, err := s.txIndexer.CreateTx(ctx, storage.CreateTxDto{
		PluginID:      policy.PluginID,
		PolicyID:      policy.ID,
		ChainID:       common.Bitcoin,
		TokenID:       "",
		FromPublicKey: policy.PublicKey,
		ToPublicKey:   "",
		ProposedTxHex: hex.EncodeToString(txBuf.Bytes()),
	})
	if err != nil {
		return types.PluginKeysignRequest{}, fmt.Errorf("failed to create tx: %w", err)
	}

	var msgs []types.KeysignMessage
	for i := range tx.Inputs {
		hashToSign, er := s.sdk.CalculateInputSignatureHash(tx, i)
		if er != nil {
			return types.PluginKeysignRequest{}, fmt.Errorf("failed to calculate input signature hash: %w", er)
		}

		msgHash := sha256.Sum256(hashToSign)
		msgs = append(msgs, types.KeysignMessage{
			TxIndexerID:  txToTrack.ID.String(),
			Message:      base64.StdEncoding.EncodeToString(hashToSign),
			Hash:         base64.StdEncoding.EncodeToString(msgHash[:]),
			HashFunction: types.HashFunction_SHA256,
			Chain:        common.Bitcoin,
		})
	}

	return types.PluginKeysignRequest{
		KeysignRequest: types.KeysignRequest{
			PublicKey: policy.PublicKey,
			Messages:  msgs,
			PolicyID:  policy.ID,
			PluginID:  policy.PluginID.String(),
		},
		Transaction: base64.StdEncoding.EncodeToString(txBuf.Bytes()),
	}, nil
}
