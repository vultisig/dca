package xrp

import (
	"context"
	"errors"
	"fmt"

	"github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/common"
)

type Network struct {
	swap   *SwapService
	signer *SignerService
	client AccountInfoProvider
}

func NewNetwork(
	swap *SwapService,
	signer *SignerService,
	client AccountInfoProvider,
) *Network {
	return &Network{
		swap:   swap,
		signer: signer,
		client: client,
	}
}

func (n *Network) Swap(ctx context.Context, policy types.PluginPolicy, from From, to To) (string, error) {
	if to.Chain == common.XRP {
		return "", errors.New("xrp: can't swap XRP to XRP")
	}

	// Fetch dynamic XRP network data
	sequence, err := n.client.GetAccountInfo(ctx, from.Address)
	if err != nil {
		return "", fmt.Errorf("xrp: failed to get account sequence: %w", err)
	}

	// Update from struct with fetched sequence
	from.Sequence = sequence

	// Find best swap route
	txData, _, err := n.swap.FindBestAmountOut(ctx, from, to)
	if err != nil {
		return "", fmt.Errorf("xrp: failed to find best amount out: %w", err)
	}

	// Sign and broadcast transaction
	txHash, err := n.signer.SignAndBroadcast(ctx, policy, txData)
	if err != nil {
		return "", fmt.Errorf("xrp: failed to sign and broadcast: %w", err)
	}

	return txHash, nil
}