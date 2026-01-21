package cosmos

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/common"
)

// Network orchestrates Cosmos transaction operations
type Network struct {
	Swap       *SwapService
	Send       *SendService
	SignerSend *SignerService
	SignerSwap *SignerService
	client     AccountInfoProvider
}

// NewNetwork creates a new Cosmos Network
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

// SendPayment sends ATOM to a destination address
func (n *Network) SendPayment(
	ctx context.Context,
	policy types.PluginPolicy,
	fromAddress string,
	toAddress string,
	amountUatom uint64,
	pubKeyHex string,
) (string, error) {
	// Check balance before signing
	accountInfo, err := n.client.GetAccount(ctx, fromAddress)
	if err != nil {
		return "", fmt.Errorf("cosmos: failed to get account info: %w", err)
	}
	if accountInfo.Balance < amountUatom {
		return "", fmt.Errorf("cosmos: insufficient balance: have %d uatom, need %d uatom", accountInfo.Balance, amountUatom)
	}

	// Build transfer transaction
	txData, signBytes, err := n.Send.BuildTransfer(ctx, fromAddress, toAddress, amountUatom, pubKeyHex)
	if err != nil {
		return "", fmt.Errorf("cosmos: failed to build transfer: %w", err)
	}

	// Decode pubkey for signing
	pubKey, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return "", fmt.Errorf("cosmos: failed to decode pubkey: %w", err)
	}

	// Sign and broadcast transaction
	txHash, err := n.SignerSend.SignAndBroadcast(ctx, policy, txData, signBytes, pubKey)
	if err != nil {
		return "", fmt.Errorf("cosmos: failed to sign and broadcast: %w", err)
	}

	return txHash, nil
}

// SwapAssets performs a swap from ATOM to another asset via THORChain
func (n *Network) SwapAssets(
	ctx context.Context,
	policy types.PluginPolicy,
	from From,
	to To,
) (string, error) {
	if to.Chain == common.GaiaChain {
		return "", errors.New("cosmos: can't swap ATOM to ATOM")
	}

	// Get account info for sequence and balance
	accountInfo, err := n.client.GetAccount(ctx, from.Address)
	if err != nil {
		return "", fmt.Errorf("cosmos: failed to get account info: %w", err)
	}

	// Check sufficient balance before signing
	if accountInfo.Balance < from.Amount {
		return "", fmt.Errorf("cosmos: insufficient balance: have %d uatom, need %d uatom", accountInfo.Balance, from.Amount)
	}

	// Update from struct with fetched data
	from.AccountNumber = accountInfo.AccountNumber
	from.Sequence = accountInfo.Sequence

	// Find best swap route
	txData, signBytes, _, err := n.Swap.FindBestAmountOut(ctx, from, to)
	if err != nil {
		return "", fmt.Errorf("cosmos: failed to find best amount out: %w", err)
	}

	// Decode pubkey for signing
	pubKey, err := hex.DecodeString(from.PubKey)
	if err != nil {
		return "", fmt.Errorf("cosmos: failed to decode pubkey: %w", err)
	}

	// Sign and broadcast transaction
	txHash, err := n.SignerSwap.SignAndBroadcast(ctx, policy, txData, signBytes, pubKey)
	if err != nil {
		return "", fmt.Errorf("cosmos: failed to sign and broadcast: %w", err)
	}

	return txHash, nil
}

