package rune

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/common"
)

// Network orchestrates THORChain (RUNE) transaction operations
type Network struct {
	Swap       *SwapService
	Send       *SendService
	SignerSend *SignerService
	SignerSwap *SignerService
	client     AccountInfoProvider
}

// NewNetwork creates a new THORChain Network
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

// SendPayment sends RUNE to a destination address
func (n *Network) SendPayment(
	ctx context.Context,
	policy types.PluginPolicy,
	fromAddress string,
	toAddress string,
	amountRune uint64,
	pubKeyHex string,
) (string, error) {
	// Check balance before signing
	accountInfo, err := n.client.GetAccount(ctx, fromAddress)
	if err != nil {
		return "", fmt.Errorf("rune: failed to get account info: %w", err)
	}
	if accountInfo.Balance < amountRune {
		return "", fmt.Errorf("rune: insufficient balance: have %d, need %d", accountInfo.Balance, amountRune)
	}

	// Build transfer transaction
	txData, signBytes, err := n.Send.BuildTransfer(ctx, fromAddress, toAddress, amountRune, pubKeyHex)
	if err != nil {
		return "", fmt.Errorf("rune: failed to build transfer: %w", err)
	}

	// Decode pubkey for signing
	pubKey, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return "", fmt.Errorf("rune: failed to decode pubkey: %w", err)
	}

	// Sign and broadcast transaction
	txHash, err := n.SignerSend.SignAndBroadcast(ctx, policy, txData, signBytes, pubKey)
	if err != nil {
		return "", fmt.Errorf("rune: failed to sign and broadcast: %w", err)
	}

	return txHash, nil
}

// SwapAssets performs a swap from RUNE to another asset via THORChain
func (n *Network) SwapAssets(
	ctx context.Context,
	policy types.PluginPolicy,
	from From,
	to To,
) (string, error) {
	if to.Chain == common.THORChain && to.AssetID == from.AssetID {
		return "", errors.New("rune: can't swap same asset to same asset")
	}

	// Get account info for sequence and balance
	accountInfo, err := n.client.GetAccount(ctx, from.Address)
	if err != nil {
		return "", fmt.Errorf("rune: failed to get account info: %w", err)
	}

	// Check sufficient balance before signing
	if accountInfo.Balance < from.Amount {
		return "", fmt.Errorf("rune: insufficient balance: have %d, need %d", accountInfo.Balance, from.Amount)
	}

	// Update from struct with fetched data
	from.AccountNumber = accountInfo.AccountNumber
	from.Sequence = accountInfo.Sequence

	// Find best swap route
	txData, signBytes, _, err := n.Swap.FindBestAmountOut(ctx, from, to)
	if err != nil {
		return "", fmt.Errorf("rune: failed to find best amount out: %w", err)
	}

	// Decode pubkey for signing
	pubKey, err := hex.DecodeString(from.PubKey)
	if err != nil {
		return "", fmt.Errorf("rune: failed to decode pubkey: %w", err)
	}

	// Sign and broadcast transaction
	txHash, err := n.SignerSwap.SignAndBroadcast(ctx, policy, txData, signBytes, pubKey)
	if err != nil {
		return "", fmt.Errorf("rune: failed to sign and broadcast: %w", err)
	}

	return txHash, nil
}

