package maya

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/common"
)

// Network orchestrates MayaChain transaction operations
type Network struct {
	Swap       *SwapService
	Send       *SendService
	SignerSend *SignerService
	SignerSwap *SignerService
	client     AccountInfoProvider
}

// NewNetwork creates a new MayaChain Network
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

// SendPayment sends CACAO to a destination address
func (n *Network) SendPayment(
	ctx context.Context,
	policy types.PluginPolicy,
	fromAddress string,
	toAddress string,
	amount uint64,
	pubKeyHex string,
) (string, error) {
	// Build transfer transaction
	txData, signBytes, err := n.Send.BuildTransfer(ctx, fromAddress, toAddress, amount, pubKeyHex)
	if err != nil {
		return "", fmt.Errorf("maya: failed to build transfer: %w", err)
	}

	// Decode pubkey for signing
	pubKey, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return "", fmt.Errorf("maya: failed to decode pubkey: %w", err)
	}

	// Sign and broadcast transaction
	txHash, err := n.SignerSend.SignAndBroadcast(ctx, policy, txData, signBytes, pubKey)
	if err != nil {
		return "", fmt.Errorf("maya: failed to sign and broadcast: %w", err)
	}

	return txHash, nil
}

// SwapAssets performs a swap from CACAO to another asset via MayaChain DEX
func (n *Network) SwapAssets(
	ctx context.Context,
	policy types.PluginPolicy,
	from From,
	to To,
) (string, error) {
	if to.Chain == common.MayaChain {
		return "", errors.New("maya: can't swap CACAO to CACAO")
	}

	// Get account info for sequence
	accountInfo, err := n.client.GetAccount(ctx, from.Address)
	if err != nil {
		return "", fmt.Errorf("maya: failed to get account info: %w", err)
	}

	// Update from struct with fetched data
	from.AccountNumber = accountInfo.AccountNumber
	from.Sequence = accountInfo.Sequence

	// Find best swap route
	txData, signBytes, _, err := n.Swap.FindBestAmountOut(ctx, from, to)
	if err != nil {
		return "", fmt.Errorf("maya: failed to find best amount out: %w", err)
	}

	// Decode pubkey for signing
	pubKey, err := hex.DecodeString(from.PubKey)
	if err != nil {
		return "", fmt.Errorf("maya: failed to decode pubkey: %w", err)
	}

	// Sign and broadcast transaction
	txHash, err := n.SignerSwap.SignAndBroadcast(ctx, policy, txData, signBytes, pubKey)
	if err != nil {
		return "", fmt.Errorf("maya: failed to sign and broadcast: %w", err)
	}

	return txHash, nil
}

