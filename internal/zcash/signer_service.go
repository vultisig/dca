package zcash

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/vultisig/recipes/sdk/zcash"
	"github.com/vultisig/verifier/plugin/keysign"
	"github.com/vultisig/verifier/plugin/tx_indexer"
	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/storage"
	"github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/common"
)

// SignerService handles Zcash transaction signing and broadcasting
type SignerService struct {
	sdk       *zcash.SDK
	signer    *keysign.Signer
	txIndexer *tx_indexer.Service
}

// NewSignerService creates a new Zcash signer service
func NewSignerService(
	client TxBroadcaster,
	signer *keysign.Signer,
	txIndexer *tx_indexer.Service,
) *SignerService {
	return &SignerService{
		sdk:       zcash.NewSDK(client),
		signer:    signer,
		txIndexer: txIndexer,
	}
}

// UnsignedTx represents an unsigned Zcash transaction with all necessary info for signing
type UnsignedTx struct {
	Inputs    []TxInput
	Outputs   []*TxOutput
	PubKey    []byte
	RawBytes  []byte
	SigHashes [][]byte // Pre-computed signature hashes for each input
}

// SignAndBroadcast signs the transaction and broadcasts it to the network
func (s *SignerService) SignAndBroadcast(
	ctx context.Context,
	policy types.PluginPolicy,
	unsignedTx *UnsignedTx,
) (string, error) {
	if unsignedTx == nil {
		return "", fmt.Errorf("zcash: unsigned transaction is nil")
	}

	keysignRequest, err := s.buildKeysignRequest(ctx, policy, unsignedTx)
	if err != nil {
		return "", fmt.Errorf("zcash: failed to build keysign request: %w", err)
	}

	signatures, err := s.signer.Sign(ctx, keysignRequest)
	if err != nil {
		return "", fmt.Errorf("zcash: failed to sign transaction: %w", err)
	}

	// Convert local UnsignedTx to SDK UnsignedTx
	sdkUnsignedTx := toSDKUnsignedTx(unsignedTx)

	signedTx, err := s.sdk.Sign(sdkUnsignedTx, signatures)
	if err != nil {
		return "", fmt.Errorf("zcash: failed to apply signatures: %w", err)
	}

	txHash, err := s.sdk.Broadcast(signedTx)
	if err != nil {
		return "", fmt.Errorf("zcash: failed to broadcast transaction: %w", err)
	}

	return txHash, nil
}

func (s *SignerService) buildKeysignRequest(
	ctx context.Context,
	policy types.PluginPolicy,
	unsignedTx *UnsignedTx,
) (types.PluginKeysignRequest, error) {
	// Serialize transaction with embedded metadata (pubkey + sighashes)
	// This allows the verifier's tx_indexer to extract the metadata for signature lookup
	dataWithMetadata := zcash.SerializeWithMetadata(unsignedTx.RawBytes, unsignedTx.SigHashes, unsignedTx.PubKey)
	txB64 := base64.StdEncoding.EncodeToString(dataWithMetadata)

	txToTrack, err := s.txIndexer.CreateTx(ctx, storage.CreateTxDto{
		PluginID:      policy.PluginID,
		PolicyID:      policy.ID,
		ChainID:       common.Zcash,
		TokenID:       "",
		FromPublicKey: policy.PublicKey,
		ToPublicKey:   "",
		ProposedTxHex: txB64,
	})
	if err != nil {
		return types.PluginKeysignRequest{}, fmt.Errorf("zcash: failed to create tx: %w", err)
	}

	var msgs []types.KeysignMessage
	for _, sigHash := range unsignedTx.SigHashes {
		msgHash := sha256.Sum256(sigHash)
		msgs = append(msgs, types.KeysignMessage{
			TxIndexerID:  txToTrack.ID.String(),
			Message:      base64.StdEncoding.EncodeToString(sigHash),
			Hash:         base64.StdEncoding.EncodeToString(msgHash[:]),
			HashFunction: types.HashFunction_SHA256,
			Chain:        common.Zcash,
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

// toSDKUnsignedTx converts local UnsignedTx to SDK UnsignedTx
func toSDKUnsignedTx(tx *UnsignedTx) *zcash.UnsignedTx {
	inputs := make([]zcash.TxInput, len(tx.Inputs))
	for i, in := range tx.Inputs {
		inputs[i] = zcash.TxInput{
			TxHash:   in.TxHash,
			Index:    in.Index,
			Value:    in.Value,
			Script:   in.Script,
			Sequence: in.Sequence,
		}
	}

	outputs := make([]*zcash.TxOutput, len(tx.Outputs))
	for i, out := range tx.Outputs {
		outputs[i] = &zcash.TxOutput{
			Value:  out.Value,
			Script: out.Script,
		}
	}

	return &zcash.UnsignedTx{
		Inputs:    inputs,
		Outputs:   outputs,
		PubKey:    tx.PubKey,
		RawBytes:  tx.RawBytes,
		SigHashes: tx.SigHashes,
	}
}
