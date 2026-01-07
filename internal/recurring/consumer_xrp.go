package recurring

import (
	"context"
	"fmt"
	"strconv"

	"github.com/sirupsen/logrus"
	"github.com/vultisig/dca/internal/xrp"
	"github.com/vultisig/mobile-tss-lib/tss"
	"github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/address"
	"github.com/vultisig/vultisig-go/common"
)

func (c *Consumer) xrpPubToAddress(rootPub string, pluginID string) (string, string, error) {
	vaultContent, err := c.vault.GetVault(common.GetVaultBackupFilename(rootPub, pluginID))
	if err != nil {
		return "", "", fmt.Errorf("failed to get vault content: %w", err)
	}

	vlt, err := common.DecryptVaultFromBackup(c.vaultSecret, vaultContent)
	if err != nil {
		return "", "", fmt.Errorf("failed to decrypt vault: %w", err)
	}

	childPub, err := tss.GetDerivedPubKey(rootPub, vlt.GetHexChainCode(), common.XRP.GetDerivePath(), false)
	if err != nil {
		return "", "", fmt.Errorf("failed to get derived pubkey: %w", err)
	}

	addr, err := address.GetXRPAddress(childPub)
	if err != nil {
		return "", "", fmt.Errorf("failed to get XRP address: %w", err)
	}

	return addr, childPub, nil
}

func (c *Consumer) handleXrpSend(
	ctx context.Context,
	pol *types.PluginPolicy,
	fromAsset string,
	recipients []Recipient,
) error {
	if len(recipients) == 0 {
		return fmt.Errorf("recipients list is empty")
	}

	// Validate that only native XRP is supported
	if fromAsset != "" {
		return fmt.Errorf("XRP send only supports native XRP, got token: %q", fromAsset)
	}

	fromAddressStr, childPubKey, err := c.xrpPubToAddress(pol.PublicKey, string(pol.PluginID))
	if err != nil {
		return fmt.Errorf("failed to get XRP address from policy PublicKey: %w", err)
	}

	// Fetch sequence once
	sequence, err := c.xrp.Send.GetSequence(ctx, fromAddressStr)
	if err != nil {
		return fmt.Errorf("failed to get XRP sequence: %w", err)
	}

	// Process each recipient sequentially
	for i, recipient := range recipients {
		txHash, err := c.sendToXrpRecipient(ctx, pol, fromAddressStr, childPubKey, recipient, sequence)
		if err != nil {
			return fmt.Errorf("failed at recipient[%d] %s: %w", i, recipient.ToAddress, err)
		}

		c.logger.WithFields(logrus.Fields{
			"policyID":  pol.ID.String(),
			"toAddress": recipient.ToAddress,
			"txHash":    txHash,
		}).Info("XRP send completed")

		// Increment sequence for next transaction
		sequence++
	}
	return nil
}

func (c *Consumer) sendToXrpRecipient(
	ctx context.Context,
	pol *types.PluginPolicy,
	fromAddress string,
	childPubKey string,
	recipient Recipient,
	sequence uint32,
) (string, error) {
	amountDrops, err := parseUint64(recipient.Amount)
	if err != nil {
		return "", fmt.Errorf("failed to parse amount: %w", err)
	}

	sendTx, err := c.xrp.Send.BuildPaymentWithSequence(ctx, fromAddress, recipient.ToAddress, amountDrops, childPubKey, sequence)
	if err != nil {
		return "", fmt.Errorf("failed to build XRP payment: %w", err)
	}

	txHash, err := c.xrp.SignerSend.SignAndBroadcast(ctx, *pol, sendTx)
	if err != nil {
		return "", fmt.Errorf("failed to sign & broadcast: %w", err)
	}

	return txHash, nil
}

func (c *Consumer) handleXrpSwap(
	ctx context.Context,
	pol *types.PluginPolicy,
	toAssetMap map[string]any,
	fromAmount, toAsset, toAddress string,
) error {
	fromAddressStr, childPubKey, err := c.xrpPubToAddress(pol.PublicKey, string(pol.PluginID))
	if err != nil {
		return fmt.Errorf("failed to get XRP address from policy PublicKey: %w", err)
	}

	fromAmountDrops, err := parseUint64(fromAmount)
	if err != nil {
		return fmt.Errorf("failed to parse fromAmount: %w", err)
	}

	toChainStr, ok := toAssetMap["chain"].(string)
	if !ok {
		return fmt.Errorf("failed to get toAsset.chain")
	}

	toChainTyped, err := common.FromString(toChainStr)
	if err != nil {
		return fmt.Errorf("failed to parse toAsset.chain: %w", err)
	}

	from := xrp.From{
		Address: fromAddressStr,
		Amount:  fromAmountDrops,
		PubKey:  childPubKey,
		// Sequence will be auto-fetched by network
	}

	to := xrp.To{
		Chain:   toChainTyped,
		AssetID: toAsset,
		Address: toAddress,
	}

	c.logger.WithFields(logrus.Fields{
		"policyID":    pol.ID.String(),
		"fromAddress": fromAddressStr,
		"fromAmount":  fromAmountDrops,
		"toChain":     toChainTyped.String(),
		"toAsset":     toAsset,
		"toAddress":   toAddress,
	}).Info("handling XRP swap")

	txHash, err := c.xrp.SwapAssets(ctx, *pol, from, to)
	if err != nil {
		// Record failed swap transaction
		c.metrics.RecordSwapTransactionWithFallback("XRP", toAsset, common.XRP.String(), toChainTyped.String(), false)
		return fmt.Errorf("failed to execute XRP swap: %w", err)
	}

	// Record successful swap transaction
	c.metrics.RecordSwapTransactionWithFallback("XRP", toAsset, common.XRP.String(), toChainTyped.String(), true)
	c.logger.WithField("txHash", txHash).Info("XRP swap executed successfully")
	return nil
}

func parseUint64(s string) (uint64, error) {
	return strconv.ParseUint(s, 10, 64)
}

