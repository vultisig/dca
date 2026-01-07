package tron

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/common"
)

// USDT TRC-20 contract address on TRON mainnet
const USDTContractAddress = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

// Default fee limit for TRC-20 transfers (in SUN, 1 TRX = 1,000,000 SUN)
// 30 TRX should be sufficient for most TRC-20 transfers
const DefaultTRC20FeeLimit = 30_000_000

// Network orchestrates TRON transaction operations
type Network struct {
	Swap       *SwapService
	Send       *SendService
	SignerSend *SignerService
	SignerSwap *SignerService
	client     AccountInfoProvider
}

// NewNetwork creates a new TRON Network
func NewNetwork(
	swap *SwapService,
	send *SendService,
	signerSend *SignerService,
	signerSwap *SignerService,
	client AccountInfoProvider,
) *Network {
	return &Network{
		Swap:       swap,
		Send:       send,
		SignerSend: signerSend,
		SignerSwap: signerSwap,
		client:     client,
	}
}

// SendPayment sends TRX to a destination address
func (n *Network) SendPayment(
	ctx context.Context,
	policy types.PluginPolicy,
	fromAddress string,
	toAddress string,
	amountSun uint64,
	pubKey []byte,
) (string, error) {
	// Build transfer transaction
	txData, _, err := n.Send.BuildTransfer(ctx, fromAddress, toAddress, amountSun)
	if err != nil {
		return "", fmt.Errorf("tron: failed to build transfer: %w", err)
	}

	// Sign and broadcast transaction
	txHash, err := n.SignerSend.SignAndBroadcast(ctx, policy, txData, pubKey)
	if err != nil {
		return "", fmt.Errorf("tron: failed to sign and broadcast: %w", err)
	}

	return txHash, nil
}

// SendTRC20 sends TRC-20 tokens (like USDT) to a destination address
func (n *Network) SendTRC20(
	ctx context.Context,
	policy types.PluginPolicy,
	fromAddress string,
	toAddress string,
	contractAddress string,
	amount *big.Int,
	pubKey []byte,
) (string, error) {
	// Build TRC-20 transfer transaction
	txData, _, err := n.Send.BuildTRC20Transfer(
		ctx,
		fromAddress,
		toAddress,
		contractAddress,
		amount,
		DefaultTRC20FeeLimit,
	)
	if err != nil {
		return "", fmt.Errorf("tron: failed to build TRC20 transfer: %w", err)
	}

	// Sign and broadcast transaction
	txHash, err := n.SignerSend.SignAndBroadcast(ctx, policy, txData, pubKey)
	if err != nil {
		return "", fmt.Errorf("tron: failed to sign and broadcast TRC20: %w", err)
	}

	return txHash, nil
}

// SwapAssets performs a swap from TRX/TRC-20 to another asset via THORChain
func (n *Network) SwapAssets(
	ctx context.Context,
	policy types.PluginPolicy,
	from From,
	to To,
	pubKey []byte,
) (string, error) {
	// Check if swapping same asset to same asset
	if to.Chain == common.Tron && to.AssetID == from.AssetID {
		return "", errors.New("tron: can't swap same asset to same asset")
	}

	// Find best swap route
	txData, _, err := n.Swap.FindBestAmountOut(ctx, from, to)
	if err != nil {
		return "", fmt.Errorf("tron: failed to find best amount out: %w", err)
	}

	// Sign and broadcast transaction
	txHash, err := n.SignerSwap.SignAndBroadcast(ctx, policy, txData, pubKey)
	if err != nil {
		return "", fmt.Errorf("tron: failed to sign and broadcast: %w", err)
	}

	return txHash, nil
}

