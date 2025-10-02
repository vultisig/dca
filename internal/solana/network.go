package solana

import (
	"context"
	"fmt"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/vultisig/dca/internal/status"
	sdk "github.com/vultisig/recipes/sdk/solana"
	"github.com/vultisig/verifier/plugin/keysign"
	"github.com/vultisig/verifier/plugin/tx_indexer"
	txindrpc "github.com/vultisig/verifier/plugin/tx_indexer/pkg/rpc"
	"github.com/vultisig/verifier/types"
)

type Network struct {
	swapService  *swapService
	signer       *signerService
	tokenAccount *tokenAccountService
}

func NewNetwork(
	ctx context.Context,
	rpcURL string,
	providers []Provider,
	signer *keysign.Signer,
	txIndexer *tx_indexer.Service,
) (*Network, error) {
	rpcClient := rpc.New(rpcURL)

	_, err := rpcClient.GetVersion(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Solana RPC: %w", err)
	}

	txIndRpc, err := txindrpc.NewSolana(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Solana RPC: %w", err)
	}

	return &Network{
		swapService: newSwapService(rpcClient, providers),
		signer: newSignerService(
			sdk.NewSDK(rpcClient),
			rpcClient,
			signer,
			txIndexer,
			status.NewStatus(txIndRpc),
		),
		tokenAccount: newTokenAccountService(rpcClient),
	}, nil
}

func (n *Network) Swap(ctx context.Context, policy types.PluginPolicy, from From, to To) (string, error) {
	ownerPubKey, err := solana.PublicKeyFromBase58(from.Address)
	if err != nil {
		return "", fmt.Errorf("invalid owner public key: %w", err)
	}

	if to.AssetID != "" {
		mintPubKey, er := solana.PublicKeyFromBase58(to.AssetID)
		if er != nil {
			return "", fmt.Errorf("invalid mint public key: %w", er)
		}

		ata, er := n.tokenAccount.GetAssociatedTokenAddress(ownerPubKey, mintPubKey)
		if er != nil {
			return "", fmt.Errorf("failed to get associated token address: %w", er)
		}

		exists, er := n.tokenAccount.CheckAccountExists(ctx, ata)
		if er != nil {
			return "", fmt.Errorf("failed to check if ATA exists: %w", er)
		}

		if !exists {
			createTx, er2 := n.tokenAccount.BuildCreateATATransaction(ctx, ownerPubKey, ownerPubKey, mintPubKey)
			if er2 != nil {
				return "", fmt.Errorf("failed to build create ATA transaction: %w", er2)
			}

			createTxBytes, er2 := createTx.MarshalBinary()
			if er2 != nil {
				return "", fmt.Errorf("failed to serialize create ATA transaction: %w", er2)
			}

			createTxHash, er2 := n.signer.SignAndBroadcast(ctx, policy, createTxBytes)
			if er2 != nil {
				return "", fmt.Errorf("failed to create ATA: %w", er2)
			}

			er2 = n.signer.WaitForConfirmation(ctx, createTxHash)
			if er2 != nil {
				return "", fmt.Errorf("failed to wait for ATA creation confirmation: %w", er2)
			}
		}
	}

	swapTx, err := n.swapService.FindBestAmountOut(ctx, from, to)
	if err != nil {
		return "", fmt.Errorf("failed to build swap transaction: %w", err)
	}

	txHash, err := n.signer.SignAndBroadcast(ctx, policy, swapTx)
	if err != nil {
		return "", fmt.Errorf("failed to sign and broadcast swap: %w", err)
	}

	return txHash, nil
}
