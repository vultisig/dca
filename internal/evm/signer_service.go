package evm

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	ecommon "github.com/ethereum/go-ethereum/common"
	etypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/vultisig/mobile-tss-lib/tss"
	"github.com/vultisig/recipes/chain/evm/ethereum"
	"github.com/vultisig/recipes/engine"
	"github.com/vultisig/recipes/sdk/evm"
	"github.com/vultisig/verifier/plugin/keysign"
	"github.com/vultisig/verifier/plugin/tx_indexer"
	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/storage"
	"github.com/vultisig/verifier/types"
	rcommon "github.com/vultisig/vultisig-go/common"
)

type signerService struct {
	sdk       *evm.SDK
	chain     rcommon.Chain
	signer    *keysign.Signer
	txIndexer *tx_indexer.Service
}

func newSignerService(
	sdk *evm.SDK,
	chain rcommon.Chain,
	signer *keysign.Signer,
	txIndexer *tx_indexer.Service,
) *signerService {
	return &signerService{
		sdk:       sdk,
		chain:     chain,
		signer:    signer,
		txIndexer: txIndexer,
	}
}

func (s *signerService) SignAndBroadcast(
	ctx context.Context,
	fromChain rcommon.Chain,
	policy types.PluginPolicy,
	unsignedTx []byte,
) (string, error) {
	recipe, err := policy.GetRecipe()
	if err != nil {
		return "", fmt.Errorf("failed to unpack recipe: %w", err)
	}

	eng, er := engine.NewEngine()
	if er != nil {
		return "", fmt.Errorf("failed to create engine: %w", er)
	}
	_, er = eng.Evaluate(recipe, fromChain, unsignedTx)
	if er != nil {
		return "", fmt.Errorf("failed to evaluate tx: %w", er)
	}

	keysignRequest, err := s.buildKeysignRequest(ctx, policy, unsignedTx)
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

	var signature tss.KeysignResponse
	for _, sig := range signatures {
		signature = sig
	}

	tx, err := s.broadcast(ctx, unsignedTx, signature)
	if err != nil {
		return "", fmt.Errorf("failed to broadcast transaction: %w", err)
	}

	return tx.Hash().Hex(), nil
}

func (s *signerService) buildKeysignRequest(
	ctx context.Context,
	policy types.PluginPolicy,
	unsignedTx []byte,
) (types.PluginKeysignRequest, error) {
	txHex := base64.StdEncoding.EncodeToString(unsignedTx)

	txData, err := ethereum.DecodeUnsignedPayload(unsignedTx)
	if err != nil {
		return types.PluginKeysignRequest{}, fmt.Errorf("ethereum.DecodeUnsignedPayload: %w", err)
	}

	evmID, err := s.chain.EvmID()
	if err != nil {
		return types.PluginKeysignRequest{}, fmt.Errorf("failed to get EVM ID: %w", err)
	}

	txHashToSign := etypes.LatestSignerForChainID(evmID).Hash(etypes.NewTx(txData))

	txToTrack, err := s.txIndexer.CreateTx(ctx, storage.CreateTxDto{
		PluginID:      policy.PluginID,
		PolicyID:      policy.ID,
		ChainID:       s.chain,
		TokenID:       "",
		FromPublicKey: policy.PublicKey,
		ToPublicKey:   "",
		ProposedTxHex: txHex,
	})
	if err != nil {
		return types.PluginKeysignRequest{}, fmt.Errorf("s.txIndexer.CreateTx: %w", err)
	}

	msgHash := sha256.Sum256(txHashToSign.Bytes())

	return types.PluginKeysignRequest{
		KeysignRequest: types.KeysignRequest{
			PublicKey: policy.PublicKey,
			Messages: []types.KeysignMessage{
				{
					TxIndexerID:  txToTrack.ID.String(),
					Message:      base64.StdEncoding.EncodeToString(txHashToSign.Bytes()),
					Chain:        s.chain,
					Hash:         base64.StdEncoding.EncodeToString(msgHash[:]),
					HashFunction: types.HashFunction_SHA256,
				},
			},
			PolicyID: policy.ID,
			PluginID: policy.PluginID.String(),
		},
		Transaction: base64.StdEncoding.EncodeToString(unsignedTx),
	}, nil
}

func (s *signerService) broadcast(
	ctx context.Context,
	unsignedTx []byte,
	signature tss.KeysignResponse,
) (*etypes.Transaction, error) {
	tx, err := s.sdk.Send(
		ctx,
		unsignedTx,
		ecommon.Hex2Bytes(signature.R),
		ecommon.Hex2Bytes(signature.S),
		ecommon.Hex2Bytes(signature.RecoveryID),
	)
	if err != nil {
		return nil, fmt.Errorf("s.sdk.Send: %w", err)
	}

	return tx, nil
}
