package solana

import (
	"context"
	"fmt"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	sdk "github.com/vultisig/recipes/sdk/solana"
	"github.com/vultisig/verifier/plugin/keysign"
	"github.com/vultisig/verifier/plugin/tx_indexer"
	txindrpc "github.com/vultisig/verifier/plugin/tx_indexer/pkg/rpc"
	"github.com/vultisig/verifier/types"

	"github.com/vultisig/dca/internal/status"
	itypes "github.com/vultisig/dca/internal/types"
)

type Network struct {
	swapService  *swapService
	signerSend   *signerService
	signerSwap   *signerService
	tokenAccount *tokenAccountService
	sendService  *sendService
}

func NewNetwork(
	ctx context.Context,
	rpcURL string,
	providers []Provider,
	signerSend *keysign.Signer,
	signerSwap *keysign.Signer,
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

	signerSdk := sdk.NewSDK(rpcClient)
	signerStatus := status.NewStatus(txIndRpc)

	return &Network{
		swapService: newSwapService(rpcClient, providers),
		signerSend: newSignerService(
			signerSdk,
			rpcClient,
			signerSend,
			txIndexer,
			signerStatus,
		),
		signerSwap: newSignerService(
			signerSdk,
			rpcClient,
			signerSwap,
			txIndexer,
			signerStatus,
		),
		tokenAccount: newTokenAccountService(rpcClient),
		sendService:  newSendService(rpcClient),
	}, nil
}

func (n *Network) Swap(ctx context.Context, policy types.PluginPolicy, from From, to To) (string, error) {
	ownerPubKey, err := solana.PublicKeyFromBase58(from.Address)
	if err != nil {
		return "", fmt.Errorf("invalid owner public key: %w", err)
	}

	if from.AssetID != "" {
		err = n.ensureATAExists(ctx, policy, ownerPubKey, from.AssetID, "source")
		if err != nil {
			return "", fmt.Errorf("failed to ensure source ATA: %w", err)
		}
	}

	if to.AssetID != "" {
		err = n.ensureATAExists(ctx, policy, ownerPubKey, to.AssetID, "destination")
		if err != nil {
			return "", fmt.Errorf("failed to ensure destination ATA: %w", err)
		}
	}

	// wSOL is always legacy SPL token program
	wsolAta, err := n.tokenAccount.GetAssociatedTokenAddress(ownerPubKey, solana.SolMint, solana.TokenProgramID)
	if err != nil {
		return "", fmt.Errorf("failed to get wSOL associated token address: %w", err)
	}

	wsolBalance, err := n.tokenAccount.GetTokenBalance(ctx, wsolAta)
	if err != nil {
		return "", fmt.Errorf("failed to get wSOL balance: %w", err)
	}

	if wsolBalance > 0 {
		closeWsolTx, err := n.tokenAccount.BuildCloseTokenAccountTransaction(ctx, ownerPubKey, wsolAta, solana.TokenProgramID)
		if err != nil {
			return "", fmt.Errorf("failed to build close wSOL account transaction: %w", err)
		}

		if closeWsolTx != nil {
			closeWsolTxBytes, err := closeWsolTx.MarshalBinary()
			if err != nil {
				return "", fmt.Errorf("failed to serialize close wSOL transaction: %w", err)
			}

			_, err = n.signBroadcastWait(ctx, policy, itypes.OperationSwap, closeWsolTxBytes)
			if err != nil {
				return "", fmt.Errorf("failed to execute: %w", err)
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

		for _, setupTxBytes := range setupTxs {
			_, er := n.signBroadcastWait(ctx, policy, itypes.OperationSwap, setupTxBytes)
			if er != nil {
				return "", fmt.Errorf("failed to execute: %w", er)
			}
		}
	}

	swapTx, err := n.swapService.FindBestAmountOut(ctx, from, to)
	if err != nil {
		return "", fmt.Errorf("failed to build swap transaction: %w", err)
	}

	txHash, err := n.signBroadcastWait(ctx, policy, itypes.OperationSwap, swapTx)
	if err != nil {
		return "", fmt.Errorf("failed to execute: %w", err)
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

		for _, cleanupTxBytes := range cleanupTxs {
			_, er := n.signBroadcastWait(ctx, policy, itypes.OperationSwap, cleanupTxBytes)
			if er != nil {
				return "", fmt.Errorf("failed to execute: %w", er)
			}
		}
	}

	return txHash, nil
}

func (n *Network) ensureATAExists(
	ctx context.Context,
	policy types.PluginPolicy,
	ownerPubKey solana.PublicKey,
	assetID string,
	label string,
) error {
	mintPubKey, err := solana.PublicKeyFromBase58(assetID)
	if err != nil {
		return fmt.Errorf("invalid %s mint public key: %w", label, err)
	}

	tokenProgram, err := n.tokenAccount.GetTokenProgram(ctx, mintPubKey)
	if err != nil {
		return fmt.Errorf("failed to get token program for %s: %w", label, err)
	}

	ata, err := n.tokenAccount.GetAssociatedTokenAddress(ownerPubKey, mintPubKey, tokenProgram)
	if err != nil {
		return fmt.Errorf("failed to get %s associated token address: %w", label, err)
	}

	exists, err := n.tokenAccount.CheckAccountExists(ctx, ata)
	if err != nil {
		return fmt.Errorf("failed to check if %s ATA exists: %w", label, err)
	}

	if !exists {
		createTx, err := n.tokenAccount.BuildCreateATATransaction(ctx, ownerPubKey, ownerPubKey, mintPubKey, tokenProgram)
		if err != nil {
			return fmt.Errorf("failed to build create %s ATA transaction: %w", label, err)
		}

		createTxBytes, err := createTx.MarshalBinary()
		if err != nil {
			return fmt.Errorf("failed to serialize create %s ATA transaction: %w", label, err)
		}

		_, err = n.signBroadcastWait(ctx, policy, itypes.OperationSwap, createTxBytes)
		if err != nil {
			return fmt.Errorf("failed to create %s ATA: %w", label, err)
		}
	}

	return nil
}

func (n *Network) Send(
	ctx context.Context,
	policy types.PluginPolicy,
	from solana.PublicKey,
	to solana.PublicKey,
	mint string,
	amount uint64,
) (string, error) {
	var txBytes []byte
	var err error

	if mint == "" {
		txBytes, err = n.sendService.BuildNativeTransfer(ctx, from, to, amount)
		if err != nil {
			return "", fmt.Errorf("failed to build native transfer: %w", err)
		}
	} else {
		mintPubKey, er := solana.PublicKeyFromBase58(mint)
		if er != nil {
			return "", fmt.Errorf("invalid mint address: %w", er)
		}

		tokenProgram, err := n.tokenAccount.GetTokenProgram(ctx, mintPubKey)
		if err != nil {
			return "", fmt.Errorf("failed to get token program: %w", err)
		}

		destATA, err := n.tokenAccount.GetAssociatedTokenAddress(to, mintPubKey, tokenProgram)
		if err != nil {
			return "", fmt.Errorf("failed to get destination ATA: %w", err)
		}

		exists, err := n.tokenAccount.CheckAccountExists(ctx, destATA)
		if err != nil {
			return "", fmt.Errorf("failed to check if destination ATA exists: %w", err)
		}

		if !exists {
			createTx, err := n.tokenAccount.BuildCreateATATransaction(ctx, from, to, mintPubKey, tokenProgram)
			if err != nil {
				return "", fmt.Errorf("failed to build create destination ATA transaction: %w", err)
			}

			createTxBytes, err := createTx.MarshalBinary()
			if err != nil {
				return "", fmt.Errorf("failed to serialize create destination ATA transaction: %w", err)
			}

			_, err = n.signBroadcastWait(ctx, policy, itypes.OperationSend, createTxBytes)
			if err != nil {
				return "", fmt.Errorf("failed to create destination ATA: %w", err)
			}
		}

		txBytes, err = n.sendService.BuildSPLTransfer(ctx, mintPubKey, from, to, amount, tokenProgram)
		if err != nil {
			return "", fmt.Errorf("failed to build SPL transfer: %w", err)
		}
	}

	txHash, err := n.signBroadcastWait(ctx, policy, itypes.OperationSend, txBytes)
	if err != nil {
		return "", fmt.Errorf("failed to sign and broadcast: %w", err)
	}

	return txHash, nil
}

func (n *Network) signBroadcastWait(ctx context.Context, policy types.PluginPolicy, op string, txBytes []byte) (string, error) {
	var signer *signerService
	switch op {
	case itypes.OperationSend:
		signer = n.signerSend
	case itypes.OperationSwap:
		signer = n.signerSwap
	default:
		return "", fmt.Errorf("no signer for operation %q", op)
	}

	if signer == nil {
		return "", fmt.Errorf("nil signer for operation %q", op)
	}

	hash, err := signer.SignAndBroadcast(ctx, policy, txBytes)
	if err != nil {
		return "", fmt.Errorf("failed to sign and broadcast: %w", err)
	}

	err = signer.WaitForConfirmation(ctx, hash)
	if err != nil {
		return "", fmt.Errorf("failed to wait for confirmation: %w", err)
	}
	return hash, nil
}
