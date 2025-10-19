package solana

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/vultisig/dca/internal/status"
	"github.com/vultisig/recipes/engine"
	sdk "github.com/vultisig/recipes/sdk/solana"
	"github.com/vultisig/verifier/plugin/keysign"
	"github.com/vultisig/verifier/plugin/tx_indexer"
	txrpc "github.com/vultisig/verifier/plugin/tx_indexer/pkg/rpc"
	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/storage"
	"github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/common"
)

type signerService struct {
	sdk       *sdk.SDK
	rpcClient *rpc.Client
	signer    *keysign.Signer
	txIndexer *tx_indexer.Service
	status    *status.Status
}

func newSignerService(
	sdk *sdk.SDK,
	rpcClient *rpc.Client,
	signer *keysign.Signer,
	txIndexer *tx_indexer.Service,
	status *status.Status,
) *signerService {
	return &signerService{
		sdk:       sdk,
		rpcClient: rpcClient,
		signer:    signer,
		txIndexer: txIndexer,
		status:    status,
	}
}

func (s *signerService) SignAndBroadcast(
	ctx context.Context,
	policy types.PluginPolicy,
	txBytes []byte,
) (string, error) {
	recipe, err := policy.GetRecipe()
	if err != nil {
		return "", fmt.Errorf("failed to unpack recipe: %w", err)
	}

	eng, err := engine.NewEngine()
	if err != nil {
		return "", fmt.Errorf("failed to create engine: %w", err)
	}

	_, err = eng.Evaluate(recipe, common.Solana, txBytes)
	if err != nil {
		return "", fmt.Errorf(
			"failed to evaluate tx (base64: %s): %w",
			base64.StdEncoding.EncodeToString(txBytes),
			err,
		)
	}

	keysignRequest, err := s.buildKeysignRequest(ctx, policy, txBytes)
	if err != nil {
		return "", fmt.Errorf("failed to build keysign request: %w", err)
	}

	signatures, err := s.signer.Sign(ctx, keysignRequest)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	if len(signatures) != 1 {
		return "", fmt.Errorf("expected 1 signature, got %d", len(signatures))
	}

	signedTx, err := s.sdk.Sign(txBytes, signatures)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	err = s.sdk.Broadcast(ctx, signedTx)
	if err != nil {
		return "", fmt.Errorf("failed to broadcast transaction: %w", err)
	}

	solTx, err := solana.TransactionFromBytes(signedTx)
	if err != nil {
		return "", fmt.Errorf("failed to parse transaction: %w", err)
	}

	// First sig is Tx Hash
	return solTx.Signatures[0].String(), nil
}

func (s *signerService) WaitForConfirmation(ctx context.Context, signature string) error {
	txStatus, err := s.status.WaitMined(ctx, signature)
	if err != nil {
		return fmt.Errorf("failed to wait for confirmation: %w", err)
	}

	if txStatus != txrpc.TxOnChainSuccess {
		return fmt.Errorf("transaction failed with status: %s", txStatus)
	}

	return nil
}

func (s *signerService) buildKeysignRequest(
	ctx context.Context,
	policy types.PluginPolicy,
	txBytes []byte,
) (types.PluginKeysignRequest, error) {
	txHex := base64.StdEncoding.EncodeToString(txBytes)

	txToTrack, err := s.txIndexer.CreateTx(ctx, storage.CreateTxDto{
		PluginID:      policy.PluginID,
		PolicyID:      policy.ID,
		ChainID:       common.Solana,
		TokenID:       "",
		FromPublicKey: policy.PublicKey,
		ToPublicKey:   "",
		ProposedTxHex: txHex,
	})
	if err != nil {
		return types.PluginKeysignRequest{}, fmt.Errorf("failed to create tx: %w", err)
	}

	hashToSign, err := s.sdk.MessageHash(txBytes)
	if err != nil {
		return types.PluginKeysignRequest{}, fmt.Errorf("failed to compute hash to sign: %w", err)
	}

	return types.PluginKeysignRequest{
		KeysignRequest: types.KeysignRequest{
			PublicKey: policy.PublicKey,
			Messages: []types.KeysignMessage{
				{
					TxIndexerID:  txToTrack.ID.String(),
					Message:      base64.StdEncoding.EncodeToString(hashToSign),
					Chain:        common.Solana,
					Hash:         base64.StdEncoding.EncodeToString(hashToSign),
					HashFunction: types.HashFunction_SHA256,
				},
			},
			PolicyID: policy.ID,
			PluginID: policy.PluginID.String(),
		},
		Transaction: base64.StdEncoding.EncodeToString(txBytes),
	}, nil
}
