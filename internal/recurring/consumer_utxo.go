package recurring

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/dca/internal/btc"
	"github.com/vultisig/dca/internal/dash"
	"github.com/vultisig/dca/internal/utxo"
	"github.com/vultisig/dca/internal/zcash"
	"github.com/vultisig/mobile-tss-lib/tss"
	btcsdk "github.com/vultisig/recipes/sdk/btc"
	"github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/address"
	"github.com/vultisig/vultisig-go/common"
)


func (c *Consumer) btcPubToAddress(rootPub string, pluginID string) (btcutil.Address, *btcutil.AddressPubKey, error) {
	vaultContent, err := c.vault.GetVault(common.GetVaultBackupFilename(rootPub, pluginID))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get vault content: %w", err)
	}

	vlt, err := common.DecryptVaultFromBackup(c.vaultSecret, vaultContent)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt vault: %w", err)
	}

	childPub, err := tss.GetDerivedPubKey(rootPub, vlt.GetHexChainCode(), common.Bitcoin.GetDerivePath(), false)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get derived pubkey: %w", err)
	}

	addr, err := address.GetBitcoinAddress(childPub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get address: %w", err)
	}

	btcAddr, err := btcutil.DecodeAddress(addr, &chaincfg.MainNetParams)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode BTC address: %w", err)
	}

	pubKeyBytes, err := hex.DecodeString(childPub)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid derived ECDSA public key: %w", err)
	}
	pub, err := btcutil.NewAddressPubKey(pubKeyBytes, &chaincfg.MainNetParams)
	if err != nil {
		return nil, nil, fmt.Errorf("fail to get public key hash: %w", err)
	}

	return btcAddr, pub, nil
}

func (c *Consumer) handleBtcSwap(
	ctx context.Context,
	pol *types.PluginPolicy,
	toAssetMap map[string]any,
	fromAmount, toAsset, toAddress string,
) error {
	fromAddressTyped, childPub, err := c.btcPubToAddress(pol.PublicKey, string(pol.PluginID))
	if err != nil {
		return fmt.Errorf("failed to get BTC address from policy PublicKey: %w", err)
	}

	fromAmountInt, ok := new(big.Int).SetString(fromAmount, 10)
	if !ok {
		return fmt.Errorf("failed to parse fromAmount: %s", fromAmount)
	}
	if !fromAmountInt.IsUint64() {
		return fmt.Errorf("fromAmount too large for uint64: %s", fromAmount)
	}
	fromAmountSats := fromAmountInt.Uint64()

	toChainStr, ok := toAssetMap["chain"].(string)
	if !ok {
		return fmt.Errorf("failed to get toAsset.chain")
	}

	toChainTyped, err := common.FromString(toChainStr)
	if err != nil {
		return fmt.Errorf("failed to parse toAsset.chain: %w", err)
	}

	from := btc.From{
		PubKey:  childPub,
		Address: fromAddressTyped,
		Amount:  fromAmountSats,
	}

	to := btc.To{
		Chain:   toChainTyped,
		AssetID: toAsset,
		Address: toAddress,
	}

	c.logger.WithFields(logrus.Fields{
		"policyID":    pol.ID.String(),
		"fromAddress": fromAddressTyped.String(),
		"fromAmount":  fromAmountSats,
		"toChain":     toChainTyped.String(),
		"toAsset":     toAsset,
		"toAddress":   toAddress,
	}).Info("handling BTC swap")

	txHash, err := c.btc.Swap(ctx, *pol, from, to)
	if err != nil {
		// Record failed swap transaction
		c.metrics.RecordSwapTransactionWithFallback("BTC", toAsset, common.Bitcoin.String(), toChainTyped.String(), false)
		return fmt.Errorf("failed to execute BTC swap: %w", err)
	}

	// Record successful swap transaction
	c.metrics.RecordSwapTransactionWithFallback("BTC", toAsset, common.Bitcoin.String(), toChainTyped.String(), true)
	c.logger.WithField("txHash", txHash).Info("BTC swap executed successfully")
	return nil
}

func (c *Consumer) handleBtcSend(
	ctx context.Context,
	pol *types.PluginPolicy,
	recipients []Recipient,
) error {
	if len(recipients) == 0 {
		return fmt.Errorf("recipients list is empty")
	}

	fromAddressTyped, childPub, err := c.btcPubToAddress(pol.PublicKey, string(pol.PluginID))
	if err != nil {
		return fmt.Errorf("failed to get BTC address from policy PublicKey: %w", err)
	}

	from := btc.From{
		PubKey:  childPub,
		Address: fromAddressTyped,
	}

	// Fetch all UTXOs once
	availableUTXOs, err := c.btc.FetchUTXOs(ctx, fromAddressTyped.String())
	if err != nil {
		return fmt.Errorf("failed to fetch UTXOs: %w", err)
	}

	// Process each recipient sequentially
	for i, recipient := range recipients {
		txHash, usedUTXOs, changeUTXO, err := c.sendToBtcRecipient(ctx, pol, from, recipient, availableUTXOs)
		if err != nil {
			return fmt.Errorf("failed at recipient[%d] %s: %w", i, recipient.ToAddress, err)
		}

		c.logger.WithFields(logrus.Fields{
			"policyID":  pol.ID.String(),
			"toAddress": recipient.ToAddress,
			"txHash":    txHash,
		}).Info("BTC send completed")

		// Update available UTXOs: remove used, add change
		availableUTXOs = btc.UpdateAvailableUTXOs(availableUTXOs, usedUTXOs, changeUTXO)
	}
	return nil
}

func (c *Consumer) sendToBtcRecipient(
	ctx context.Context,
	pol *types.PluginPolicy,
	from btc.From,
	recipient Recipient,
	availableUTXOs []btcsdk.UTXO,
) (string, []btcsdk.UTXO, *btcsdk.UTXO, error) {
	amountInt, ok := new(big.Int).SetString(recipient.Amount, 10)
	if !ok {
		return "", nil, nil, fmt.Errorf("failed to parse amount: %s", recipient.Amount)
	}
	if !amountInt.IsUint64() {
		return "", nil, nil, fmt.Errorf("amount too large for uint64: %s", recipient.Amount)
	}
	amountSats := amountInt.Uint64()

	return c.btc.Send(ctx, *pol, from, recipient.ToAddress, amountSats, availableUTXOs)
}


func (c *Consumer) ltcPubToAddress(rootPub string, pluginID string) (btcutil.Address, []byte, error) {
	vaultContent, err := c.vault.GetVault(common.GetVaultBackupFilename(rootPub, pluginID))
	if err != nil {
		return nil, nil, fmt.Errorf("[LTC] failed to get vault content: %w", err)
	}

	vlt, err := common.DecryptVaultFromBackup(c.vaultSecret, vaultContent)
	if err != nil {
		return nil, nil, fmt.Errorf("[LTC] failed to decrypt vault: %w", err)
	}

	childPub, err := tss.GetDerivedPubKey(rootPub, vlt.GetHexChainCode(), common.Litecoin.GetDerivePath(), false)
	if err != nil {
		return nil, nil, fmt.Errorf("[LTC] failed to get derived pubkey: %w", err)
	}

	addr, err := address.GetLitecoinAddress(childPub)
	if err != nil {
		return nil, nil, fmt.Errorf("[LTC] failed to get address: %w", err)
	}

	ltcAddr, err := btcutil.DecodeAddress(addr, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("[LTC] failed to decode address: %w", err)
	}

	pubKeyBytes, err := hex.DecodeString(childPub)
	if err != nil {
		return nil, nil, fmt.Errorf("[LTC] invalid derived ECDSA public key: %w", err)
	}

	return ltcAddr, pubKeyBytes, nil
}

func (c *Consumer) handleLtcSend(
	ctx context.Context,
	pol *types.PluginPolicy,
	recipients []Recipient,
) error {
	if len(recipients) == 0 {
		return fmt.Errorf("recipients list is empty")
	}

	fromAddressTyped, childPub, err := c.ltcPubToAddress(pol.PublicKey, string(pol.PluginID))
	if err != nil {
		return fmt.Errorf("failed to get LTC address from policy PublicKey: %w", err)
	}

	from := utxo.From{
		PubKey:  childPub,
		Address: fromAddressTyped,
	}

	// Fetch all UTXOs once
	availableUTXOs, err := c.ltc.FetchUTXOs(ctx, fromAddressTyped.String())
	if err != nil {
		return fmt.Errorf("failed to fetch UTXOs: %w", err)
	}

	// Process each recipient sequentially
	for i, recipient := range recipients {
		txHash, usedUTXOs, changeUTXO, err := c.sendToLtcRecipient(ctx, pol, from, recipient, availableUTXOs)
		if err != nil {
			return fmt.Errorf("failed at recipient[%d] %s: %w", i, recipient.ToAddress, err)
		}

		c.logger.WithFields(logrus.Fields{
			"policyID":  pol.ID.String(),
			"toAddress": recipient.ToAddress,
			"txHash":    txHash,
		}).Info("LTC send completed")

		// Update available UTXOs: remove used, add change
		availableUTXOs = utxo.UpdateAvailableUTXOs(availableUTXOs, usedUTXOs, changeUTXO)
	}
	return nil
}

func (c *Consumer) sendToLtcRecipient(
	ctx context.Context,
	pol *types.PluginPolicy,
	from utxo.From,
	recipient Recipient,
	availableUTXOs []btcsdk.UTXO,
) (string, []btcsdk.UTXO, *btcsdk.UTXO, error) {
	amountInt, ok := new(big.Int).SetString(recipient.Amount, 10)
	if !ok {
		return "", nil, nil, fmt.Errorf("failed to parse amount: %s", recipient.Amount)
	}
	if !amountInt.IsUint64() {
		return "", nil, nil, fmt.Errorf("amount too large for uint64: %s", recipient.Amount)
	}
	amountSats := amountInt.Uint64()

	return c.ltc.Send(ctx, *pol, from, recipient.ToAddress, amountSats, availableUTXOs)
}

func (c *Consumer) handleLtcSwap(
	ctx context.Context,
	pol *types.PluginPolicy,
	toAssetMap map[string]any,
	fromAmount, toAsset, toAddress string,
) error {
	fromAddressTyped, childPub, err := c.ltcPubToAddress(pol.PublicKey, string(pol.PluginID))
	if err != nil {
		return fmt.Errorf("failed to get LTC address from policy PublicKey: %w", err)
	}

	fromAmountInt, ok := new(big.Int).SetString(fromAmount, 10)
	if !ok {
		return fmt.Errorf("failed to parse fromAmount: %s", fromAmount)
	}
	if !fromAmountInt.IsUint64() {
		return fmt.Errorf("fromAmount too large for uint64: %s", fromAmount)
	}
	fromAmountSats := fromAmountInt.Uint64()

	toChainStr, ok := toAssetMap["chain"].(string)
	if !ok {
		return fmt.Errorf("failed to get toAsset.chain")
	}

	toChainTyped, err := common.FromString(toChainStr)
	if err != nil {
		return fmt.Errorf("failed to parse toAsset.chain: %w", err)
	}

	from := utxo.From{
		PubKey:  childPub,
		Address: fromAddressTyped,
		Amount:  fromAmountSats,
	}

	to := utxo.To{
		Chain:   toChainTyped,
		AssetID: toAsset,
		Address: toAddress,
	}

	c.logger.WithFields(logrus.Fields{
		"policyID":    pol.ID.String(),
		"fromAddress": fromAddressTyped.String(),
		"fromAmount":  fromAmountSats,
		"toChain":     toChainTyped.String(),
		"toAsset":     toAsset,
		"toAddress":   toAddress,
	}).Info("handling LTC swap")

	txHash, err := c.ltc.Swap(ctx, *pol, from, to)
	if err != nil {
		c.metrics.RecordSwapTransactionWithFallback("LTC", toAsset, common.Litecoin.String(), toChainTyped.String(), false)
		return fmt.Errorf("failed to execute LTC swap: %w", err)
	}

	c.metrics.RecordSwapTransactionWithFallback("LTC", toAsset, common.Litecoin.String(), toChainTyped.String(), true)
	c.logger.WithField("txHash", txHash).Info("LTC swap executed successfully")
	return nil
}

// ============================================================================
// Dogecoin (DOGE) handlers
// ============================================================================

func (c *Consumer) dogePubToAddress(rootPub string, pluginID string) (btcutil.Address, []byte, error) {
	vaultContent, err := c.vault.GetVault(common.GetVaultBackupFilename(rootPub, pluginID))
	if err != nil {
		return nil, nil, fmt.Errorf("[DOGE] failed to get vault content: %w", err)
	}

	vlt, err := common.DecryptVaultFromBackup(c.vaultSecret, vaultContent)
	if err != nil {
		return nil, nil, fmt.Errorf("[DOGE] failed to decrypt vault: %w", err)
	}

	childPub, err := tss.GetDerivedPubKey(rootPub, vlt.GetHexChainCode(), common.Dogecoin.GetDerivePath(), false)
	if err != nil {
		return nil, nil, fmt.Errorf("[DOGE] failed to get derived pubkey: %w", err)
	}

	addr, err := address.GetDogecoinAddress(childPub)
	if err != nil {
		return nil, nil, fmt.Errorf("[DOGE] failed to get address: %w", err)
	}

	dogeAddr, err := btcutil.DecodeAddress(addr, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("[DOGE] failed to decode address: %w", err)
	}

	pubKeyBytes, err := hex.DecodeString(childPub)
	if err != nil {
		return nil, nil, fmt.Errorf("[DOGE] invalid derived ECDSA public key: %w", err)
	}

	return dogeAddr, pubKeyBytes, nil
}

func (c *Consumer) handleDogeSend(
	ctx context.Context,
	pol *types.PluginPolicy,
	recipients []Recipient,
) error {
	if len(recipients) == 0 {
		return fmt.Errorf("recipients list is empty")
	}

	fromAddressTyped, childPub, err := c.dogePubToAddress(pol.PublicKey, string(pol.PluginID))
	if err != nil {
		return fmt.Errorf("failed to get DOGE address from policy PublicKey: %w", err)
	}

	from := utxo.From{
		PubKey:  childPub,
		Address: fromAddressTyped,
	}

	// Fetch all UTXOs once
	availableUTXOs, err := c.doge.FetchUTXOs(ctx, fromAddressTyped.String())
	if err != nil {
		return fmt.Errorf("failed to fetch UTXOs: %w", err)
	}

	// Process each recipient sequentially
	for i, recipient := range recipients {
		txHash, usedUTXOs, changeUTXO, err := c.sendToDogeRecipient(ctx, pol, from, recipient, availableUTXOs)
		if err != nil {
			return fmt.Errorf("failed at recipient[%d] %s: %w", i, recipient.ToAddress, err)
		}

		c.logger.WithFields(logrus.Fields{
			"policyID":  pol.ID.String(),
			"toAddress": recipient.ToAddress,
			"txHash":    txHash,
		}).Info("DOGE send completed")

		// Update available UTXOs: remove used, add change
		availableUTXOs = utxo.UpdateAvailableUTXOs(availableUTXOs, usedUTXOs, changeUTXO)
	}
	return nil
}

func (c *Consumer) sendToDogeRecipient(
	ctx context.Context,
	pol *types.PluginPolicy,
	from utxo.From,
	recipient Recipient,
	availableUTXOs []btcsdk.UTXO,
) (string, []btcsdk.UTXO, *btcsdk.UTXO, error) {
	amountInt, ok := new(big.Int).SetString(recipient.Amount, 10)
	if !ok {
		return "", nil, nil, fmt.Errorf("failed to parse amount: %s", recipient.Amount)
	}
	if !amountInt.IsUint64() {
		return "", nil, nil, fmt.Errorf("amount too large for uint64: %s", recipient.Amount)
	}
	amountSats := amountInt.Uint64()

	return c.doge.Send(ctx, *pol, from, recipient.ToAddress, amountSats, availableUTXOs)
}

func (c *Consumer) handleDogeSwap(
	ctx context.Context,
	pol *types.PluginPolicy,
	toAssetMap map[string]any,
	fromAmount, toAsset, toAddress string,
) error {
	fromAddressTyped, childPub, err := c.dogePubToAddress(pol.PublicKey, string(pol.PluginID))
	if err != nil {
		return fmt.Errorf("failed to get DOGE address from policy PublicKey: %w", err)
	}

	fromAmountInt, ok := new(big.Int).SetString(fromAmount, 10)
	if !ok {
		return fmt.Errorf("failed to parse fromAmount: %s", fromAmount)
	}
	if !fromAmountInt.IsUint64() {
		return fmt.Errorf("fromAmount too large for uint64: %s", fromAmount)
	}
	fromAmountSats := fromAmountInt.Uint64()

	toChainStr, ok := toAssetMap["chain"].(string)
	if !ok {
		return fmt.Errorf("failed to get toAsset.chain")
	}

	toChainTyped, err := common.FromString(toChainStr)
	if err != nil {
		return fmt.Errorf("failed to parse toAsset.chain: %w", err)
	}

	from := utxo.From{
		PubKey:  childPub,
		Address: fromAddressTyped,
		Amount:  fromAmountSats,
	}

	to := utxo.To{
		Chain:   toChainTyped,
		AssetID: toAsset,
		Address: toAddress,
	}

	c.logger.WithFields(logrus.Fields{
		"policyID":    pol.ID.String(),
		"fromAddress": fromAddressTyped.String(),
		"fromAmount":  fromAmountSats,
		"toChain":     toChainTyped.String(),
		"toAsset":     toAsset,
		"toAddress":   toAddress,
	}).Info("handling DOGE swap")

	txHash, err := c.doge.Swap(ctx, *pol, from, to)
	if err != nil {
		c.metrics.RecordSwapTransactionWithFallback("DOGE", toAsset, common.Dogecoin.String(), toChainTyped.String(), false)
		return fmt.Errorf("failed to execute DOGE swap: %w", err)
	}

	c.metrics.RecordSwapTransactionWithFallback("DOGE", toAsset, common.Dogecoin.String(), toChainTyped.String(), true)
	c.logger.WithField("txHash", txHash).Info("DOGE swap executed successfully")
	return nil
}

// ============================================================================
// Bitcoin Cash (BCH) handlers
// ============================================================================

func (c *Consumer) bchPubToAddress(rootPub string, pluginID string) (btcutil.Address, []byte, error) {
	vaultContent, err := c.vault.GetVault(common.GetVaultBackupFilename(rootPub, pluginID))
	if err != nil {
		return nil, nil, fmt.Errorf("[BCH] failed to get vault content: %w", err)
	}

	vlt, err := common.DecryptVaultFromBackup(c.vaultSecret, vaultContent)
	if err != nil {
		return nil, nil, fmt.Errorf("[BCH] failed to decrypt vault: %w", err)
	}

	childPub, err := tss.GetDerivedPubKey(rootPub, vlt.GetHexChainCode(), common.BitcoinCash.GetDerivePath(), false)
	if err != nil {
		return nil, nil, fmt.Errorf("[BCH] failed to get derived pubkey: %w", err)
	}

	addr, err := address.GetBitcoinCashAddress(childPub)
	if err != nil {
		return nil, nil, fmt.Errorf("[BCH] failed to get address: %w", err)
	}

	bchAddr, err := btcutil.DecodeAddress(addr, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("[BCH] failed to decode address: %w", err)
	}

	pubKeyBytes, err := hex.DecodeString(childPub)
	if err != nil {
		return nil, nil, fmt.Errorf("[BCH] invalid derived ECDSA public key: %w", err)
	}

	return bchAddr, pubKeyBytes, nil
}

func (c *Consumer) handleBchSend(
	ctx context.Context,
	pol *types.PluginPolicy,
	recipients []Recipient,
) error {
	if len(recipients) == 0 {
		return fmt.Errorf("recipients list is empty")
	}

	fromAddressTyped, childPub, err := c.bchPubToAddress(pol.PublicKey, string(pol.PluginID))
	if err != nil {
		return fmt.Errorf("failed to get BCH address from policy PublicKey: %w", err)
	}

	from := utxo.From{
		PubKey:  childPub,
		Address: fromAddressTyped,
	}

	// Fetch all UTXOs once
	availableUTXOs, err := c.bch.FetchUTXOs(ctx, fromAddressTyped.String())
	if err != nil {
		return fmt.Errorf("failed to fetch UTXOs: %w", err)
	}

	// Process each recipient sequentially
	for i, recipient := range recipients {
		txHash, usedUTXOs, changeUTXO, err := c.sendToBchRecipient(ctx, pol, from, recipient, availableUTXOs)
		if err != nil {
			return fmt.Errorf("failed at recipient[%d] %s: %w", i, recipient.ToAddress, err)
		}

		c.logger.WithFields(logrus.Fields{
			"policyID":  pol.ID.String(),
			"toAddress": recipient.ToAddress,
			"txHash":    txHash,
		}).Info("BCH send completed")

		// Update available UTXOs: remove used, add change
		availableUTXOs = utxo.UpdateAvailableUTXOs(availableUTXOs, usedUTXOs, changeUTXO)
	}
	return nil
}

func (c *Consumer) sendToBchRecipient(
	ctx context.Context,
	pol *types.PluginPolicy,
	from utxo.From,
	recipient Recipient,
	availableUTXOs []btcsdk.UTXO,
) (string, []btcsdk.UTXO, *btcsdk.UTXO, error) {
	amountInt, ok := new(big.Int).SetString(recipient.Amount, 10)
	if !ok {
		return "", nil, nil, fmt.Errorf("failed to parse amount: %s", recipient.Amount)
	}
	if !amountInt.IsUint64() {
		return "", nil, nil, fmt.Errorf("amount too large for uint64: %s", recipient.Amount)
	}
	amountSats := amountInt.Uint64()

	return c.bch.Send(ctx, *pol, from, recipient.ToAddress, amountSats, availableUTXOs)
}

func (c *Consumer) handleBchSwap(
	ctx context.Context,
	pol *types.PluginPolicy,
	toAssetMap map[string]any,
	fromAmount, toAsset, toAddress string,
) error {
	fromAddressTyped, childPub, err := c.bchPubToAddress(pol.PublicKey, string(pol.PluginID))
	if err != nil {
		return fmt.Errorf("failed to get BCH address from policy PublicKey: %w", err)
	}

	fromAmountInt, ok := new(big.Int).SetString(fromAmount, 10)
	if !ok {
		return fmt.Errorf("failed to parse fromAmount: %s", fromAmount)
	}
	if !fromAmountInt.IsUint64() {
		return fmt.Errorf("fromAmount too large for uint64: %s", fromAmount)
	}
	fromAmountSats := fromAmountInt.Uint64()

	toChainStr, ok := toAssetMap["chain"].(string)
	if !ok {
		return fmt.Errorf("failed to get toAsset.chain")
	}

	toChainTyped, err := common.FromString(toChainStr)
	if err != nil {
		return fmt.Errorf("failed to parse toAsset.chain: %w", err)
	}

	from := utxo.From{
		PubKey:  childPub,
		Address: fromAddressTyped,
		Amount:  fromAmountSats,
	}

	to := utxo.To{
		Chain:   toChainTyped,
		AssetID: toAsset,
		Address: toAddress,
	}

	c.logger.WithFields(logrus.Fields{
		"policyID":    pol.ID.String(),
		"fromAddress": fromAddressTyped.String(),
		"fromAmount":  fromAmountSats,
		"toChain":     toChainTyped.String(),
		"toAsset":     toAsset,
		"toAddress":   toAddress,
	}).Info("handling BCH swap")

	txHash, err := c.bch.Swap(ctx, *pol, from, to)
	if err != nil {
		c.metrics.RecordSwapTransactionWithFallback("BCH", toAsset, common.BitcoinCash.String(), toChainTyped.String(), false)
		return fmt.Errorf("failed to execute BCH swap: %w", err)
	}

	c.metrics.RecordSwapTransactionWithFallback("BCH", toAsset, common.BitcoinCash.String(), toChainTyped.String(), true)
	c.logger.WithField("txHash", txHash).Info("BCH swap executed successfully")
	return nil
}

// ============================================================================
// Cosmos (Gaia) handlers
// ============================================================================

// cosmosPubToAddress derives a Cosmos (Gaia) address from the root public key

func (c *Consumer) zcashPubToAddress(rootPub string, pluginID string) (string, []byte, error) {
	vaultContent, err := c.vault.GetVault(common.GetVaultBackupFilename(rootPub, pluginID))
	if err != nil {
		return "", nil, fmt.Errorf("failed to get vault content: %w", err)
	}

	vlt, err := common.DecryptVaultFromBackup(c.vaultSecret, vaultContent)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decrypt vault: %w", err)
	}

	childPub, err := tss.GetDerivedPubKey(rootPub, vlt.GetHexChainCode(), common.Zcash.GetDerivePath(), false)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get derived pubkey: %w", err)
	}

	addr, pubKeyBytes, err := zcash.GetAddressFromPubKey(childPub)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get Zcash address: %w", err)
	}

	return addr, pubKeyBytes, nil
}

func (c *Consumer) handleZcashSend(
	ctx context.Context,
	pol *types.PluginPolicy,
	recipients []Recipient,
) error {
	if len(recipients) == 0 {
		return fmt.Errorf("recipients list is empty")
	}
	if len(recipients) > 1 {
		c.logger.WithField("recipientCount", len(recipients)).Warn("multi-recipient send not yet supported, only handling first recipient")
	}

	// Extract first recipient for now
	recipient := recipients[0]
	fromAmount := recipient.Amount
	toAddress := recipient.ToAddress

	fromAddressStr, pubKeyBytes, err := c.zcashPubToAddress(pol.PublicKey, string(pol.PluginID))
	if err != nil {
		return fmt.Errorf("failed to get Zcash address from policy PublicKey: %w", err)
	}

	fromAmountZatoshis, err := parseUint64(fromAmount)
	if err != nil {
		return fmt.Errorf("failed to parse fromAmount: %w", err)
	}

	from := zcash.From{
		PubKey:  pubKeyBytes,
		Address: fromAddressStr,
		Amount:  fromAmountZatoshis,
	}

	l := c.logger.WithFields(logrus.Fields{
		"operation":   "send",
		"policyID":    pol.ID.String(),
		"fromAddress": fromAddressStr,
		"toAddress":   toAddress,
		"amount":      fromAmountZatoshis,
	})

	l.Info("handling Zcash send")

	txHash, err := c.zcash.Send(ctx, *pol, from, toAddress, fromAmountZatoshis)
	if err != nil {
		l.WithError(err).Error("failed to execute Zcash send")
		return fmt.Errorf("failed to execute Zcash send: %w", err)
	}

	l.WithField("txHash", txHash).Info("Zcash send executed successfully")
	return nil
}

func (c *Consumer) handleZcashSwap(
	ctx context.Context,
	pol *types.PluginPolicy,
	toAssetMap map[string]any,
	fromAmount, toAsset, toAddress string,
) error {
	fromAddressStr, pubKeyBytes, err := c.zcashPubToAddress(pol.PublicKey, string(pol.PluginID))
	if err != nil {
		return fmt.Errorf("failed to get Zcash address from policy PublicKey: %w", err)
	}

	fromAmountZatoshis, err := parseUint64(fromAmount)
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

	from := zcash.From{
		PubKey:  pubKeyBytes,
		Address: fromAddressStr,
		Amount:  fromAmountZatoshis,
	}

	to := zcash.To{
		Chain:   toChainTyped,
		AssetID: toAsset,
		Address: toAddress,
	}

	c.logger.WithFields(logrus.Fields{
		"policyID":    pol.ID.String(),
		"fromAddress": fromAddressStr,
		"fromAmount":  fromAmountZatoshis,
		"toChain":     toChainTyped.String(),
		"toAsset":     toAsset,
		"toAddress":   toAddress,
	}).Info("handling Zcash swap")

	txHash, err := c.zcash.Swap(ctx, *pol, from, to)
	if err != nil {
		// Record failed swap transaction
		c.metrics.RecordSwapTransactionWithFallback("ZEC", toAsset, common.Zcash.String(), toChainTyped.String(), false)
		return fmt.Errorf("failed to execute Zcash swap: %w", err)
	}

	// Record successful swap transaction
	c.metrics.RecordSwapTransactionWithFallback("ZEC", toAsset, common.Zcash.String(), toChainTyped.String(), true)
	c.logger.WithField("txHash", txHash).Info("Zcash swap executed successfully")
	return nil
}

func (c *Consumer) dashPubToAddress(rootPub string, pluginID string) (string, []byte, error) {
	vaultContent, err := c.vault.GetVault(common.GetVaultBackupFilename(rootPub, pluginID))
	if err != nil {
		return "", nil, fmt.Errorf("failed to get vault content: %w", err)
	}

	vlt, err := common.DecryptVaultFromBackup(c.vaultSecret, vaultContent)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decrypt vault: %w", err)
	}

	childPub, err := tss.GetDerivedPubKey(rootPub, vlt.GetHexChainCode(), common.Dash.GetDerivePath(), false)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get derived pubkey: %w", err)
	}

	addr, pubKeyBytes, err := dash.GetAddressFromPubKey(childPub)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get Dash address: %w", err)
	}

	return addr, pubKeyBytes, nil
}

func (c *Consumer) handleDashSend(
	ctx context.Context,
	pol *types.PluginPolicy,
	recipients []Recipient,
) error {
	if len(recipients) == 0 {
		return fmt.Errorf("recipients list is empty")
	}
	if len(recipients) > 1 {
		c.logger.WithField("recipientCount", len(recipients)).Warn("multi-recipient send not yet supported, only handling first recipient")
	}

	recipient := recipients[0]
	toAddress := recipient.ToAddress
	fromAmount := recipient.Amount

	fromAddressStr, pubKeyBytes, err := c.dashPubToAddress(pol.PublicKey, string(pol.PluginID))
	if err != nil {
		return fmt.Errorf("failed to get Dash address from policy PublicKey: %w", err)
	}

	fromAmountDuffs, err := parseUint64(fromAmount)
	if err != nil {
		return fmt.Errorf("failed to parse fromAmount: %w", err)
	}

	fromAddress, err := dash.DecodeAddress(fromAddressStr)
	if err != nil {
		return fmt.Errorf("failed to decode Dash address: %w", err)
	}

	l := c.logger.WithFields(logrus.Fields{
		"policyID":    pol.ID.String(),
		"fromAddress": fromAddressStr,
		"toAddress":   toAddress,
		"amount":      fromAmountDuffs,
	})

	l.Info("handling Dash send")

	txHash, err := c.dash.SendPayment(ctx, *pol, fromAddress, toAddress, fromAmountDuffs, pubKeyBytes)
	if err != nil {
		l.WithError(err).Error("failed to execute Dash send")
		return fmt.Errorf("failed to execute Dash send: %w", err)
	}

	l.WithField("txHash", txHash).Info("Dash send executed successfully")
	return nil
}

func (c *Consumer) handleDashSwap(
	ctx context.Context,
	pol *types.PluginPolicy,
	toAssetMap map[string]any,
	fromAmount, toAsset, toAddress string,
) error {
	fromAddressStr, pubKeyBytes, err := c.dashPubToAddress(pol.PublicKey, string(pol.PluginID))
	if err != nil {
		return fmt.Errorf("failed to get Dash address from policy PublicKey: %w", err)
	}

	fromAmountDuffs, err := parseUint64(fromAmount)
	if err != nil {
		return fmt.Errorf("failed to parse fromAmount: %w", err)
	}

	fromAddress, err := dash.DecodeAddress(fromAddressStr)
	if err != nil {
		return fmt.Errorf("failed to decode Dash address: %w", err)
	}

	toChainStr, ok := toAssetMap["chain"].(string)
	if !ok {
		return fmt.Errorf("failed to get toAsset.chain from config")
	}

	toChainTyped, err := common.FromString(toChainStr)
	if err != nil {
		return fmt.Errorf("failed to parse toAsset.chain: %w", err)
	}

	from := dash.From{
		Address: fromAddress,
		Amount:  fromAmountDuffs,
		PubKey:  pubKeyBytes,
	}

	to := dash.To{
		Chain:   toChainTyped,
		AssetID: toAsset,
		Address: toAddress,
	}

	c.logger.WithFields(logrus.Fields{
		"policyID":    pol.ID.String(),
		"fromAddress": fromAddressStr,
		"fromAmount":  fromAmountDuffs,
		"toChain":     toChainTyped.String(),
		"toAsset":     toAsset,
		"toAddress":   toAddress,
	}).Info("handling Dash swap")

	txHash, err := c.dash.SwapAssets(ctx, *pol, from, to)
	if err != nil {
		// Record failed swap transaction
		c.metrics.RecordSwapTransactionWithFallback("DASH", toAsset, common.Dash.String(), toChainTyped.String(), false)
		return fmt.Errorf("failed to execute Dash swap: %w", err)
	}

	// Record successful swap transaction
	c.metrics.RecordSwapTransactionWithFallback("DASH", toAsset, common.Dash.String(), toChainTyped.String(), true)
	c.logger.WithField("txHash", txHash).Info("Dash swap executed successfully")
	return nil
}

// convertAmountToBaseUnits converts a human-readable amount to base units (e.g., "10" USDC -> "10000000").
// Always converts - if the amount is incorrect, the policy will reject the transaction.
