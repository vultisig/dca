package thorchain_native

import (
	"context"
	"errors"
	"fmt"

	"github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/common"
)

type Network struct {
	Swap   *SwapService
	Send   *SendService
	Signer *SignerService
	client *Client
}

func NewNetwork(
	swap *SwapService,
	send *SendService,
	signer *SignerService,
	client *Client,
) *Network {
	return &Network{
		Swap:   swap,
		Send:   send,
		Signer: signer,
		client: client,
	}
}

func (n *Network) SendPayment(ctx context.Context, policy types.PluginPolicy, fromAddress, toAddress string, amountRune uint64, pubKey string) (string, error) {
	// Get account information for signing
	accountInfo, err := n.client.GetAccountInfo(ctx, fromAddress)
	if err != nil {
		return "", fmt.Errorf("thorchain: failed to get account info: %w", err)
	}

	// Build payment transaction using send service
	txData, err := n.Send.BuildPayment(ctx, fromAddress, toAddress, amountRune, pubKey)
	if err != nil {
		return "", fmt.Errorf("thorchain: failed to build payment: %w", err)
	}

	// Sign and broadcast transaction
	txHash, err := n.Signer.SignAndBroadcast(ctx, policy, txData, accountInfo.AccountNumber, accountInfo.Sequence)
	if err != nil {
		return "", fmt.Errorf("thorchain: failed to sign and broadcast: %w", err)
	}

	return txHash, nil
}

func (n *Network) SwapAssets(ctx context.Context, policy types.PluginPolicy, from From, to To) (string, error) {
	if to.Chain == common.THORChain && from.AssetID == to.AssetID {
		return "", errors.New("thorchain: can't swap same asset on THORChain")
	}

	// Fetch dynamic THORChain network data (account number and sequence)
	accountInfo, err := n.client.GetAccountInfo(ctx, from.Address)
	if err != nil {
		return "", fmt.Errorf("thorchain: failed to get account info: %w", err)
	}

	// Update from struct with fetched account info
	from.Sequence = accountInfo.Sequence
	from.AccountNumber = accountInfo.AccountNumber

	// Find best swap route
	txData, _, err := n.Swap.FindBestAmountOut(ctx, from, to)
	if err != nil {
		return "", fmt.Errorf("thorchain: failed to find best amount out: %w", err)
	}

	// Sign and broadcast transaction
	txHash, err := n.Signer.SignAndBroadcast(ctx, policy, txData, from.AccountNumber, from.Sequence)
	if err != nil {
		return "", fmt.Errorf("thorchain: failed to sign and broadcast: %w", err)
	}

	return txHash, nil
}