package xrp

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	xrpgo "github.com/xyield/xrpl-go/binary-codec"
	"github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/common"
)

type Network struct {
	Swap   *SwapService
	Send   *SendService
	Signer *SignerService
	client AccountInfoProvider
}

func NewNetwork(
	swap *SwapService,
	send *SendService,
	signer *SignerService,
	client AccountInfoProvider,
) *Network {
	return &Network{
		Swap:   swap,
		Send:   send,
		Signer: signer,
		client: client,
	}
}

func (n *Network) SendPayment(ctx context.Context, policy types.PluginPolicy, fromAddress, toAddress string, amountDrops uint64, pubKey string) (string, error) {
	// Build payment transaction using send service
	txData, err := n.Send.BuildPayment(ctx, fromAddress, toAddress, amountDrops, pubKey)
	if err != nil {
		return "", fmt.Errorf("xrp: failed to build payment: %w", err)
	}

	// Sign and broadcast transaction
	txHash, err := n.Signer.SignAndBroadcast(ctx, policy, txData)
	if err != nil {
		return "", fmt.Errorf("xrp: failed to sign and broadcast: %w", err)
	}

	return txHash, nil
}

func (n *Network) SwapAssets(ctx context.Context, policy types.PluginPolicy, from From, to To) (string, error) {
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
	txData, _, err := n.Swap.FindBestAmountOut(ctx, from, to)
	if err != nil {
		return "", fmt.Errorf("xrp: failed to find best amount out: %w", err)
	}

	// Sign and broadcast transaction
	txHash, err := n.Signer.SignAndBroadcast(ctx, policy, txData)
	if err != nil {
		return "", fmt.Errorf("xrp: failed to sign and broadcast: %w", err)
	}

	return txHash, nil
}

// buildUnsignedXRPLSimplePayment creates an unsigned Payment transaction for simple XRP transfers
func buildUnsignedXRPLSimplePayment(
	from, to string,
	amountDrops uint64,
	sequence uint32,
	feeDrops uint64,
	lastLedgerSequence uint32,
	signingPubKey string,
) ([]byte, error) {
	jsonMap := map[string]any{
		"Account":            from,
		"TransactionType":    "Payment",
		"Amount":             fmt.Sprintf("%d", amountDrops),
		"Destination":        to,
		"Fee":                fmt.Sprintf("%d", feeDrops),
		"Sequence":           int(sequence),
		"LastLedgerSequence": int(lastLedgerSequence),
		"SigningPubKey":      strings.ToUpper(strings.TrimSpace(signingPubKey)),
	}

	// Encode → Decode → Re-encode for canonical bytes
	hexStr, err := xrpgo.Encode(jsonMap)
	if err != nil {
		return nil, fmt.Errorf("encode failed: %w", err)
	}

	decoded, err := xrpgo.Decode(strings.ToUpper(hexStr))
	if err != nil {
		return nil, fmt.Errorf("decode round-trip failed: %w", err)
	}

	canonicalHex, err := xrpgo.Encode(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-encode failed: %w", err)
	}

	txBytes, err := hex.DecodeString(canonicalHex)
	if err != nil {
		return nil, fmt.Errorf("hex to bytes failed: %w", err)
	}

	return txBytes, nil
}