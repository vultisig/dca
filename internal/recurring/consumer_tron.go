package recurring

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/vultisig/dca/internal/tron"
	"github.com/vultisig/mobile-tss-lib/tss"
	"github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/address"
	"github.com/vultisig/vultisig-go/common"
)

func (c *Consumer) tronPubToAddress(rootPub string, pluginID string) (string, []byte, error) {
	vaultContent, err := c.vault.GetVault(common.GetVaultBackupFilename(rootPub, pluginID))
	if err != nil {
		return "", nil, fmt.Errorf("failed to get vault content: %w", err)
	}

	vlt, err := common.DecryptVaultFromBackup(c.vaultSecret, vaultContent)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decrypt vault: %w", err)
	}

	childPub, err := tss.GetDerivedPubKey(rootPub, vlt.GetHexChainCode(), common.Tron.GetDerivePath(), false)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get derived pubkey: %w", err)
	}

	addr, _, _, err := address.GetAddress(rootPub, vlt.GetHexChainCode(), common.Tron)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get Tron address: %w", err)
	}

	pubKeyBytes, err := hex.DecodeString(childPub)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decode pubkey: %w", err)
	}

	return addr, pubKeyBytes, nil
}

// handleTronSend handles TRON send operations
func (c *Consumer) handleTronSend(
	ctx context.Context,
	pol *types.PluginPolicy,
	recipients []Recipient,
) error {
	if len(recipients) == 0 {
		return fmt.Errorf("recipients list is empty")
	}

	fromAddressStr, pubKeyBytes, err := c.tronPubToAddress(pol.PublicKey, string(pol.PluginID))
	if err != nil {
		return fmt.Errorf("failed to get Tron address from policy PublicKey: %w", err)
	}

	// Process each recipient sequentially
	for i, recipient := range recipients {
		amountSun, err := parseUint64(recipient.Amount)
		if err != nil {
			return fmt.Errorf("failed to parse amount for recipient[%d]: %w", i, err)
		}

		txHash, err := c.tron.SendPayment(ctx, *pol, fromAddressStr, recipient.ToAddress, amountSun, pubKeyBytes)
		if err != nil {
			return fmt.Errorf("failed at recipient[%d] %s: %w", i, recipient.ToAddress, err)
		}

		c.logger.WithFields(logrus.Fields{
			"policyID":  pol.ID.String(),
			"toAddress": recipient.ToAddress,
			"txHash":    txHash,
		}).Info("Tron send completed")
	}
	return nil
}

// handleTronSwap handles TRON swap operations via THORChain
func (c *Consumer) handleTronSwap(
	ctx context.Context,
	pol *types.PluginPolicy,
	toAssetMap map[string]any,
	fromAmount, toAsset, toAddress string,
) error {
	fromAddressStr, pubKeyBytes, err := c.tronPubToAddress(pol.PublicKey, string(pol.PluginID))
	if err != nil {
		return fmt.Errorf("failed to get Tron address from policy PublicKey: %w", err)
	}

	fromAmountSun, err := parseUint64(fromAmount)
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

	from := tron.From{
		Address: fromAddressStr,
		Amount:  fromAmountSun,
		PubKey:  hex.EncodeToString(pubKeyBytes),
	}

	to := tron.To{
		Chain:   toChainTyped,
		AssetID: toAsset,
		Address: toAddress,
	}

	c.logger.WithFields(logrus.Fields{
		"policyID":    pol.ID.String(),
		"fromAddress": fromAddressStr,
		"fromAmount":  fromAmountSun,
		"toChain":     toChainTyped.String(),
		"toAsset":     toAsset,
		"toAddress":   toAddress,
	}).Info("handling Tron swap")

	txHash, err := c.tron.SwapAssets(ctx, *pol, from, to, pubKeyBytes)
	if err != nil {
		c.metrics.RecordSwapTransactionWithFallback("TRX", toAsset, common.Tron.String(), toChainTyped.String(), false)
		return fmt.Errorf("failed to execute Tron swap: %w", err)
	}

	c.metrics.RecordSwapTransactionWithFallback("TRX", toAsset, common.Tron.String(), toChainTyped.String(), true)
	c.logger.WithField("txHash", txHash).Info("Tron swap executed successfully")
	return nil
}
