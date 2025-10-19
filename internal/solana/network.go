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

	if from.AssetID != "" {
		mintPubKey, er := solana.PublicKeyFromBase58(from.AssetID)
		if er != nil {
			return "", fmt.Errorf("invalid source mint public key: %w", er)
		}

		ata, er := n.tokenAccount.GetAssociatedTokenAddress(ownerPubKey, mintPubKey)
		if er != nil {
			return "", fmt.Errorf("failed to get source associated token address: %w", er)
		}

		exists, er := n.tokenAccount.CheckAccountExists(ctx, ata)
		if er != nil {
			return "", fmt.Errorf("failed to check if source ATA exists: %w", er)
		}

		if !exists {
			createTx, er2 := n.tokenAccount.BuildCreateATATransaction(ctx, ownerPubKey, ownerPubKey, mintPubKey)
			if er2 != nil {
				return "", fmt.Errorf("failed to build create source ATA transaction: %w", er2)
			}

			createTxBytes, er2 := createTx.MarshalBinary()
			if er2 != nil {
				return "", fmt.Errorf("failed to serialize create source ATA transaction: %w", er2)
			}

			createTxHash, er2 := n.signer.SignAndBroadcast(ctx, policy, createTxBytes)
			if er2 != nil {
				return "", fmt.Errorf("failed to create source ATA: %w", er2)
			}

			er2 = n.signer.WaitForConfirmation(ctx, createTxHash)
			if er2 != nil {
				return "", fmt.Errorf("failed to wait for source ATA creation confirmation: %w", er2)
			}
		}
	}

	if to.AssetID != "" {
		mintPubKey, er := solana.PublicKeyFromBase58(to.AssetID)
		if er != nil {
			return "", fmt.Errorf("invalid destination mint public key: %w", er)
		}

		ata, er := n.tokenAccount.GetAssociatedTokenAddress(ownerPubKey, mintPubKey)
		if er != nil {
			return "", fmt.Errorf("failed to get destination associated token address: %w", er)
		}

		exists, er := n.tokenAccount.CheckAccountExists(ctx, ata)
		if er != nil {
			return "", fmt.Errorf("failed to check if destination ATA exists: %w", er)
		}

		if !exists {
			createTx, er2 := n.tokenAccount.BuildCreateATATransaction(ctx, ownerPubKey, ownerPubKey, mintPubKey)
			if er2 != nil {
				return "", fmt.Errorf("failed to build create destination ATA transaction: %w", er2)
			}

			createTxBytes, er2 := createTx.MarshalBinary()
			if er2 != nil {
				return "", fmt.Errorf("failed to serialize create destination ATA transaction: %w", er2)
			}

			createTxHash, er2 := n.signer.SignAndBroadcast(ctx, policy, createTxBytes)
			if er2 != nil {
				return "", fmt.Errorf("failed to create destination ATA: %w", er2)
			}

			er2 = n.signer.WaitForConfirmation(ctx, createTxHash)
			if er2 != nil {
				return "", fmt.Errorf("failed to wait for destination ATA creation confirmation: %w", er2)
			}
		}
	}

	wsolAta, err := n.tokenAccount.GetAssociatedTokenAddress(ownerPubKey, solana.SolMint)
	if err != nil {
		return "", fmt.Errorf("failed to get wSOL associated token address: %w", err)
	}

	wsolBalance, err := n.tokenAccount.GetTokenBalance(ctx, wsolAta)
	if err != nil {
		return "", fmt.Errorf("failed to get wSOL balance: %w", err)
	}

	if wsolBalance > 0 {
		closeWsolTx, err := n.tokenAccount.BuildCloseTokenAccountTransaction(ctx, ownerPubKey, wsolAta)
		if err != nil {
			return "", fmt.Errorf("failed to build close wSOL account transaction: %w", err)
		}

		if closeWsolTx != nil {
			closeWsolTxBytes, err := closeWsolTx.MarshalBinary()
			if err != nil {
				return "", fmt.Errorf("failed to serialize close wSOL transaction: %w", err)
			}

			closeWsolTxHash, err := n.signer.SignAndBroadcast(ctx, policy, closeWsolTxBytes)
			if err != nil {
				return "", fmt.Errorf("failed to sign and broadcast close wSOL transaction: %w", err)
			}

			err = n.signer.WaitForConfirmation(ctx, closeWsolTxHash)
			if err != nil {
				return "", fmt.Errorf("failed to wait for close wSOL transaction confirmation: %w", err)
			}
		}
	}

	provider, setupNeeded, err := n.swapService.CheckSetupNeeded(ctx, from, to)
	if err != nil {
		return "", fmt.Errorf("failed to check setup: %w", err)
	}

	if setupNeeded {
		setupTxs, err := provider.BuildSetupTxs(ctx, from, to)
		if err != nil {
			return "", fmt.Errorf("failed to build setup transactions: %w", err)
		}

		for i, setupTxBytes := range setupTxs {
			setupTxHash, er := n.signer.SignAndBroadcast(ctx, policy, setupTxBytes)
			if er != nil {
				return "", fmt.Errorf("failed to sign and broadcast setup transaction %d: %w", i, er)
			}

			er = n.signer.WaitForConfirmation(ctx, setupTxHash)
			if er != nil {
				return "", fmt.Errorf("failed to wait for setup transaction %d confirmation: %w", i, er)
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

	err = n.signer.WaitForConfirmation(ctx, txHash)
	if err != nil {
		return "", fmt.Errorf("failed to wait for swap confirmation: %w", err)
	}

	provider, cleanupNeeded, err := n.swapService.CheckCleanupNeeded(ctx, from, to)
	if err != nil {
		return "", fmt.Errorf("failed to check cleanup: %w", err)
	}

	if cleanupNeeded {
		cleanupTxs, err := provider.BuildCleanupTxs(ctx, from, to)
		if err != nil {
			return "", fmt.Errorf("failed to build cleanup transactions: %w", err)
		}

		for i, cleanupTxBytes := range cleanupTxs {
			cleanupTxHash, er := n.signer.SignAndBroadcast(ctx, policy, cleanupTxBytes)
			if er != nil {
				return "", fmt.Errorf("failed to sign and broadcast cleanup transaction %d: %w", i, er)
			}

			er = n.signer.WaitForConfirmation(ctx, cleanupTxHash)
			if er != nil {
				return "", fmt.Errorf("failed to wait for cleanup transaction %d confirmation: %w", i, er)
			}
		}
	}

	return txHash, nil
}
