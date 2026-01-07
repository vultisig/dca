package recurring

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/vultisig/dca/internal/cosmos"
	"github.com/vultisig/dca/internal/maya"
	"github.com/vultisig/dca/internal/rune"
	"github.com/vultisig/mobile-tss-lib/tss"
	"github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/address"
	"github.com/vultisig/vultisig-go/common"
)

func (c *Consumer) cosmosPubToAddress(rootPub string, pluginID string) (string, string, error) {
	vaultContent, err := c.vault.GetVault(common.GetVaultBackupFilename(rootPub, pluginID))
	if err != nil {
		return "", "", fmt.Errorf("failed to get vault content: %w", err)
	}

	vlt, err := common.DecryptVaultFromBackup(c.vaultSecret, vaultContent)
	if err != nil {
		return "", "", fmt.Errorf("failed to decrypt vault: %w", err)
	}

	childPub, err := tss.GetDerivedPubKey(rootPub, vlt.GetHexChainCode(), common.GaiaChain.GetDerivePath(), false)
	if err != nil {
		return "", "", fmt.Errorf("failed to get derived pubkey: %w", err)
	}

	addr, _, _, err := address.GetAddress(rootPub, vlt.GetHexChainCode(), common.GaiaChain)
	if err != nil {
		return "", "", fmt.Errorf("failed to get Cosmos address: %w", err)
	}

	return addr, childPub, nil
}

// handleCosmosSend handles Cosmos (Gaia) send operations
func (c *Consumer) handleCosmosSend(
	ctx context.Context,
	pol *types.PluginPolicy,
	recipients []Recipient,
) error {
	if len(recipients) == 0 {
		return fmt.Errorf("recipients list is empty")
	}

	fromAddressStr, childPubKey, err := c.cosmosPubToAddress(pol.PublicKey, string(pol.PluginID))
	if err != nil {
		return fmt.Errorf("failed to get Cosmos address from policy PublicKey: %w", err)
	}

	// Process each recipient sequentially
	for i, recipient := range recipients {
		amountUatom, err := parseUint64(recipient.Amount)
		if err != nil {
			return fmt.Errorf("failed to parse amount for recipient[%d]: %w", i, err)
		}

		txHash, err := c.cosmos.SendPayment(ctx, *pol, fromAddressStr, recipient.ToAddress, amountUatom, childPubKey)
		if err != nil {
			return fmt.Errorf("failed at recipient[%d] %s: %w", i, recipient.ToAddress, err)
		}

		c.logger.WithFields(logrus.Fields{
			"policyID":  pol.ID.String(),
			"toAddress": recipient.ToAddress,
			"txHash":    txHash,
		}).Info("Cosmos send completed")
	}
	return nil
}

// handleCosmosSwap handles Cosmos (Gaia) swap operations via THORChain
func (c *Consumer) handleCosmosSwap(
	ctx context.Context,
	pol *types.PluginPolicy,
	toAssetMap map[string]any,
	fromAmount, toAsset, toAddress string,
) error {
	fromAddressStr, childPubKey, err := c.cosmosPubToAddress(pol.PublicKey, string(pol.PluginID))
	if err != nil {
		return fmt.Errorf("failed to get Cosmos address from policy PublicKey: %w", err)
	}

	fromAmountUatom, err := parseUint64(fromAmount)
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

	from := cosmos.From{
		Address: fromAddressStr,
		Amount:  fromAmountUatom,
		PubKey:  childPubKey,
	}

	to := cosmos.To{
		Chain:   toChainTyped,
		AssetID: toAsset,
		Address: toAddress,
	}

	c.logger.WithFields(logrus.Fields{
		"policyID":    pol.ID.String(),
		"fromAddress": fromAddressStr,
		"fromAmount":  fromAmountUatom,
		"toChain":     toChainTyped.String(),
		"toAsset":     toAsset,
		"toAddress":   toAddress,
	}).Info("handling Cosmos swap")

	txHash, err := c.cosmos.SwapAssets(ctx, *pol, from, to)
	if err != nil {
		c.metrics.RecordSwapTransactionWithFallback("ATOM", toAsset, common.GaiaChain.String(), toChainTyped.String(), false)
		return fmt.Errorf("failed to execute Cosmos swap: %w", err)
	}

	c.metrics.RecordSwapTransactionWithFallback("ATOM", toAsset, common.GaiaChain.String(), toChainTyped.String(), true)
	c.logger.WithField("txHash", txHash).Info("Cosmos swap executed successfully")
	return nil
}

// ============================================================================
// MayaChain handlers
// ============================================================================

// mayaPubToAddress derives a MayaChain address from the root public key
func (c *Consumer) mayaPubToAddress(rootPub string, pluginID string) (string, string, error) {
	vaultContent, err := c.vault.GetVault(common.GetVaultBackupFilename(rootPub, pluginID))
	if err != nil {
		return "", "", fmt.Errorf("failed to get vault content: %w", err)
	}

	vlt, err := common.DecryptVaultFromBackup(c.vaultSecret, vaultContent)
	if err != nil {
		return "", "", fmt.Errorf("failed to decrypt vault: %w", err)
	}

	childPub, err := tss.GetDerivedPubKey(rootPub, vlt.GetHexChainCode(), common.MayaChain.GetDerivePath(), false)
	if err != nil {
		return "", "", fmt.Errorf("failed to get derived pubkey: %w", err)
	}

	addr, _, _, err := address.GetAddress(rootPub, vlt.GetHexChainCode(), common.MayaChain)
	if err != nil {
		return "", "", fmt.Errorf("failed to get Maya address: %w", err)
	}

	return addr, childPub, nil
}

// handleMayaSend handles MayaChain send operations
func (c *Consumer) handleMayaSend(
	ctx context.Context,
	pol *types.PluginPolicy,
	recipients []Recipient,
) error {
	if len(recipients) == 0 {
		return fmt.Errorf("recipients list is empty")
	}

	fromAddressStr, childPubKey, err := c.mayaPubToAddress(pol.PublicKey, string(pol.PluginID))
	if err != nil {
		return fmt.Errorf("failed to get Maya address from policy PublicKey: %w", err)
	}

	// Process each recipient sequentially
	for i, recipient := range recipients {
		amount, err := parseUint64(recipient.Amount)
		if err != nil {
			return fmt.Errorf("failed to parse amount for recipient[%d]: %w", i, err)
		}

		txHash, err := c.maya.SendPayment(ctx, *pol, fromAddressStr, recipient.ToAddress, amount, childPubKey)
		if err != nil {
			return fmt.Errorf("failed at recipient[%d] %s: %w", i, recipient.ToAddress, err)
		}

		c.logger.WithFields(logrus.Fields{
			"policyID":  pol.ID.String(),
			"toAddress": recipient.ToAddress,
			"txHash":    txHash,
		}).Info("Maya send completed")
	}
	return nil
}

// handleMayaSwap handles MayaChain swap operations
func (c *Consumer) handleMayaSwap(
	ctx context.Context,
	pol *types.PluginPolicy,
	toAssetMap map[string]any,
	fromAmount, toAsset, toAddress string,
) error {
	fromAddressStr, childPubKey, err := c.mayaPubToAddress(pol.PublicKey, string(pol.PluginID))
	if err != nil {
		return fmt.Errorf("failed to get Maya address from policy PublicKey: %w", err)
	}

	fromAmountCacao, err := parseUint64(fromAmount)
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

	from := maya.From{
		Address: fromAddressStr,
		Amount:  fromAmountCacao,
		PubKey:  childPubKey,
	}

	to := maya.To{
		Chain:   toChainTyped,
		AssetID: toAsset,
		Address: toAddress,
	}

	c.logger.WithFields(logrus.Fields{
		"policyID":    pol.ID.String(),
		"fromAddress": fromAddressStr,
		"fromAmount":  fromAmountCacao,
		"toChain":     toChainTyped.String(),
		"toAsset":     toAsset,
		"toAddress":   toAddress,
	}).Info("handling Maya swap")

	txHash, err := c.maya.SwapAssets(ctx, *pol, from, to)
	if err != nil {
		c.metrics.RecordSwapTransactionWithFallback("CACAO", toAsset, common.MayaChain.String(), toChainTyped.String(), false)
		return fmt.Errorf("failed to execute Maya swap: %w", err)
	}

	c.metrics.RecordSwapTransactionWithFallback("CACAO", toAsset, common.MayaChain.String(), toChainTyped.String(), true)
	c.logger.WithField("txHash", txHash).Info("Maya swap executed successfully")
	return nil
}

// ============================================================================
// THORChain (RUNE) handlers
// ============================================================================

func (c *Consumer) runePubToAddress(rootPub string, pluginID string) (string, string, error) {
	vaultContent, err := c.vault.GetVault(common.GetVaultBackupFilename(rootPub, pluginID))
	if err != nil {
		return "", "", fmt.Errorf("failed to get vault content: %w", err)
	}

	vlt, err := common.DecryptVaultFromBackup(c.vaultSecret, vaultContent)
	if err != nil {
		return "", "", fmt.Errorf("failed to decrypt vault: %w", err)
	}

	childPub, err := tss.GetDerivedPubKey(rootPub, vlt.GetHexChainCode(), common.THORChain.GetDerivePath(), false)
	if err != nil {
		return "", "", fmt.Errorf("failed to get derived pubkey: %w", err)
	}

	addr, _, _, err := address.GetAddress(rootPub, vlt.GetHexChainCode(), common.THORChain)
	if err != nil {
		return "", "", fmt.Errorf("failed to get THORChain address: %w", err)
	}

	return addr, childPub, nil
}

func (c *Consumer) handleRuneSend(
	ctx context.Context,
	pol *types.PluginPolicy,
	recipients []Recipient,
) error {
	if len(recipients) == 0 {
		return fmt.Errorf("recipients list is empty")
	}

	fromAddressStr, childPubKey, err := c.runePubToAddress(pol.PublicKey, string(pol.PluginID))
	if err != nil {
		return fmt.Errorf("failed to get THORChain address from policy PublicKey: %w", err)
	}

	for i, recipient := range recipients {
		amount, err := parseUint64(recipient.Amount)
		if err != nil {
			return fmt.Errorf("failed to parse amount for recipient[%d]: %w", i, err)
		}

		txHash, err := c.rune.SendPayment(ctx, *pol, fromAddressStr, recipient.ToAddress, amount, childPubKey)
		if err != nil {
			return fmt.Errorf("failed at recipient[%d] %s: %w", i, recipient.ToAddress, err)
		}

		c.logger.WithFields(logrus.Fields{
			"policyID":  pol.ID.String(),
			"toAddress": recipient.ToAddress,
			"txHash":    txHash,
		}).Info("RUNE send completed")
	}
	return nil
}

func (c *Consumer) handleRuneSwap(
	ctx context.Context,
	pol *types.PluginPolicy,
	toAssetMap map[string]any,
	fromAmount, toAsset, toAddress string,
) error {
	fromAddressStr, childPubKey, err := c.runePubToAddress(pol.PublicKey, string(pol.PluginID))
	if err != nil {
		return fmt.Errorf("failed to get THORChain address from policy PublicKey: %w", err)
	}

	fromAmountRune, err := parseUint64(fromAmount)
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

	from := rune.From{
		Address: fromAddressStr,
		Amount:  fromAmountRune,
		PubKey:  childPubKey,
	}

	to := rune.To{
		Chain:   toChainTyped,
		AssetID: toAsset,
		Address: toAddress,
	}

	c.logger.WithFields(logrus.Fields{
		"policyID":    pol.ID.String(),
		"fromAddress": fromAddressStr,
		"fromAmount":  fromAmountRune,
		"toChain":     toChainTyped.String(),
		"toAsset":     toAsset,
		"toAddress":   toAddress,
	}).Info("handling RUNE swap")

	txHash, err := c.rune.SwapAssets(ctx, *pol, from, to)
	if err != nil {
		c.metrics.RecordSwapTransactionWithFallback("RUNE", toAsset, common.THORChain.String(), toChainTyped.String(), false)
		return fmt.Errorf("failed to execute RUNE swap: %w", err)
	}

	c.metrics.RecordSwapTransactionWithFallback("RUNE", toAsset, common.THORChain.String(), toChainTyped.String(), true)
	c.logger.WithField("txHash", txHash).Info("RUNE swap executed successfully")
	return nil
}

// ============================================================================
// TRON handlers
// ============================================================================

// tronPubToAddress derives a TRON address from the root public key
