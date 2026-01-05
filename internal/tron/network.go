package tron

import (
	"context"
	"errors"
	"fmt"

	"github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/common"
)

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

// SwapAssets performs a swap from TRX to another asset via THORChain
func (n *Network) SwapAssets(
	ctx context.Context,
	policy types.PluginPolicy,
	from From,
	to To,
	pubKey []byte,
) (string, error) {
	if to.Chain == common.Tron {
		return "", errors.New("tron: can't swap TRX to TRX")
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

