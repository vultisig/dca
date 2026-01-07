package recurring

import (
	"context"
	"fmt"
	"math/big"

	solanasdk "github.com/gagliardetto/solana-go"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/dca/internal/solana"
	"github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/address"
	"github.com/vultisig/vultisig-go/common"
)

func (c *Consumer) solanaPubToAddress(rootPub string, pluginID string) (string, error) {
	vaultContent, err := c.vault.GetVault(common.GetVaultBackupFilename(rootPub, pluginID))
	if err != nil {
		return "", fmt.Errorf("failed to get vault content: %w", err)
	}

	vlt, err := common.DecryptVaultFromBackup(c.vaultSecret, vaultContent)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt vault: %w", err)
	}

	addr, err := address.GetSolAddress(vlt.GetPublicKeyEddsa())
	if err != nil {
		return "", fmt.Errorf("failed to get Solana address: %w", err)
	}

	return addr, nil
}

func (c *Consumer) handleSolanaSwap(
	ctx context.Context,
	pol *types.PluginPolicy,
	toAssetMap map[string]any,
	fromAmount, fromAsset, toAsset, toAddress string,
) error {
	fromAddressTyped, err := c.solanaPubToAddress(pol.PublicKey, string(pol.PluginID))
	if err != nil {
		return fmt.Errorf("failed to get Solana address from policy PublicKey: %w", err)
	}

	fromAmountTyped, ok := new(big.Int).SetString(fromAmount, 10)
	if !ok {
		return fmt.Errorf("failed to parse fromAmount: %s", fromAmount)
	}

	toChainStr, ok := toAssetMap["chain"].(string)
	if !ok {
		return fmt.Errorf("failed to get toAsset.chain")
	}

	toChainTyped, err := common.FromString(toChainStr)
	if err != nil {
		return fmt.Errorf("failed to parse toAsset.chain: %w", err)
	}

	from := solana.From{
		Amount:  fromAmountTyped,
		AssetID: fromAsset,
		Address: fromAddressTyped,
	}

	to := solana.To{
		Chain:   toChainTyped,
		AssetID: toAsset,
		Address: toAddress,
	}

	c.logger.WithFields(logrus.Fields{
		"policyID":    pol.ID.String(),
		"fromAddress": fromAddressTyped,
		"fromAmount":  fromAmountTyped.String(),
		"toChain":     toChainTyped.String(),
		"toAsset":     toAsset,
		"toAddress":   toAddress,
	}).Info("handling Solana swap")

	txHash, err := c.solana.Swap(ctx, *pol, from, to)
	if err != nil {
		// Record failed swap transaction
		c.metrics.RecordSwapTransactionWithFallback(fromAsset, toAsset, common.Solana.String(), toChainTyped.String(), false)
		return fmt.Errorf("failed to execute Solana swap: %w", err)
	}

	// Record successful swap transaction
	c.metrics.RecordSwapTransactionWithFallback(fromAsset, toAsset, common.Solana.String(), toChainTyped.String(), true)
	c.logger.WithField("txHash", txHash).Info("Solana swap executed successfully")
	return nil
}

func (c *Consumer) handleSolanaSend(
	ctx context.Context,
	pol *types.PluginPolicy,
	fromAsset string,
	recipients []Recipient,
) error {
	if len(recipients) == 0 {
		return fmt.Errorf("recipients list is empty")
	}

	fromAddressTyped, err := c.solanaPubToAddress(pol.PublicKey, string(pol.PluginID))
	if err != nil {
		return fmt.Errorf("failed to get Solana address from policy PublicKey: %w", err)
	}

	fromPubKey, err := solanasdk.PublicKeyFromBase58(fromAddressTyped)
	if err != nil {
		return fmt.Errorf("failed to parse from address: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"operation":      "send",
		"policyID":       pol.ID.String(),
		"chain":          "solana",
		"fromAddress":    fromAddressTyped,
		"asset":          fromAsset,
		"recipientCount": len(recipients),
	}).Info("processing Solana send for multiple recipients")

	// Process each recipient sequentially
	// Solana uses blockhash (not nonce/sequence), so each tx is independent
	for i, recipient := range recipients {
		txHash, err := c.sendToSolanaRecipient(ctx, pol, fromPubKey, fromAsset, recipient)
		if err != nil {
			return fmt.Errorf("failed at recipient[%d] %s: %w", i, recipient.ToAddress, err)
		}

		c.logger.WithFields(logrus.Fields{
			"policyID":  pol.ID.String(),
			"toAddress": recipient.ToAddress,
			"txHash":    txHash,
		}).Info("Solana send completed")
	}

	return nil
}

func (c *Consumer) sendToSolanaRecipient(
	ctx context.Context,
	pol *types.PluginPolicy,
	fromPubKey solanasdk.PublicKey,
	fromAsset string,
	recipient Recipient,
) (string, error) {
	amount, err := parseUint64(recipient.Amount)
	if err != nil {
		return "", fmt.Errorf("failed to parse amount: %w", err)
	}

	toPubKey, err := solanasdk.PublicKeyFromBase58(recipient.ToAddress)
	if err != nil {
		return "", fmt.Errorf("failed to parse to address: %w", err)
	}

	txHash, err := c.solana.Send(ctx, *pol, fromPubKey, toPubKey, fromAsset, amount)
	if err != nil {
		return "", fmt.Errorf("failed to execute Solana send: %w", err)
	}

	return txHash, nil
}

