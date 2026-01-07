package recurring

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/big"

	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/dca/internal/evm"
	"github.com/vultisig/dca/internal/util"
	"github.com/vultisig/mobile-tss-lib/tss"
	evmsdk "github.com/vultisig/recipes/sdk/evm"
	rtypes "github.com/vultisig/recipes/types"
	"github.com/vultisig/verifier/plugin/scheduler"
	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/rpc"
	"github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/address"
	"github.com/vultisig/vultisig-go/common"
)

func (c *Consumer) evmPubToAddress(chain common.Chain, pub string, pluginID string) (ecommon.Address, error) {
	vaultContent, err := c.vault.GetVault(common.GetVaultBackupFilename(pub, pluginID))
	if err != nil {
		return ecommon.Address{}, fmt.Errorf("failed to get vault content: %w", err)
	}

	vlt, err := common.DecryptVaultFromBackup(c.vaultSecret, vaultContent)
	if err != nil {
		return ecommon.Address{}, fmt.Errorf("failed to decrypt vault: %w", err)
	}

	childPub, err := tss.GetDerivedPubKey(pub, vlt.GetHexChainCode(), chain.GetDerivePath(), false)
	if err != nil {
		return ecommon.Address{}, fmt.Errorf("failed to get derived pubkey: %w", err)
	}

	addr, err := address.GetEVMAddress(childPub)
	if err != nil {
		return ecommon.Address{}, fmt.Errorf("failed to get address: %w", err)
	}
	return ecommon.HexToAddress(addr), nil
}

func (c *Consumer) handleEvmSwap(
	ctx context.Context,
	pol *types.PluginPolicy,
	recipe *rtypes.Policy,
	trigger scheduler.Scheduler,
	toAssetMap map[string]any,
	fromChain common.Chain,
	fromAsset, fromAmount, toAsset, toAddress string,
) error {
	fromAssetTyped := ecommon.HexToAddress(fromAsset)
	fromAddressTyped, err := c.evmPubToAddress(fromChain, pol.PublicKey, string(pol.PluginID))
	if err != nil {
		return fmt.Errorf("failed to parse policy PublicKey: %w", err)
	}
	fromAmountTyped, ok := new(big.Int).SetString(fromAmount, 10)
	if !ok {
		return fmt.Errorf("failed to parse fromAmountStr: %w", err)
	}

	toChainStr, ok := toAssetMap["chain"].(string)
	if !ok {
		return fmt.Errorf("failed to get toAsset.chain")
	}

	toChainTyped, err := common.FromString(toChainStr)
	if err != nil {
		return fmt.Errorf("failed to parse toAsset.chain: %w", err)
	}

	network, err := c.evm.Get(fromChain)
	if err != nil {
		return fmt.Errorf("failed to get network: %w", err)
	}

	from := evm.From{
		Chain:   fromChain,
		AssetID: fromAssetTyped,
		Address: fromAddressTyped,
		Amount:  fromAmountTyped,
	}
	to := evm.To{
		Chain:   toChainTyped,
		AssetID: toAsset,
		Address: toAddress,
	}

	spender, err := network.Swap.GetApprovalSpender(ctx, from, to)
	if err != nil {
		return fmt.Errorf("failed to get approval spender from canonical router: %w", err)
	}

	l := c.logger.WithFields(logrus.Fields{
		"policyID":   trigger.PolicyID.String(),
		"spender":    spender.String(),
		"fromChain":  fromChain.String(),
		"fromAsset":  fromAssetTyped.String(),
		"fromAmount": fromAmountTyped.String(),
		"toChain":    toChainTyped.String(),
		"toAsset":    toAsset,
		"toAddress":  toAddress,
	})

	shouldApprove, approveTx, err := network.Approve.CheckAllowance(
		ctx,
		fromAssetTyped,
		fromAddressTyped,
		spender,
		fromAmountTyped,
	)
	if err != nil {
		return fmt.Errorf("failed to check allowance & build approve: %w", err)
	}
	if shouldApprove {
		l.Info("approve needed, wait mined")

		hash, er := network.SignerSwap.SignAndBroadcast(ctx, fromChain, *pol, approveTx)
		if er != nil {
			return fmt.Errorf("failed to sign & broadcast approve: %w", er)
		}
		st, er := network.Status.WaitMined(ctx, hash)
		if er != nil {
			return fmt.Errorf(
				"failed to wait approve: %s, hash=%s, chain=%s",
				st,
				hash,
				fromChain.String(),
			)
		}
		if st != rpc.TxOnChainSuccess {
			return fmt.Errorf(
				"failed to land approve: %s, hash=%s, chain=%s",
				st,
				hash,
				fromChain.String(),
			)
		}
	}

	swapTx, err := network.Swap.FindBestAmountOut(ctx, from, to)
	if err != nil {
		return fmt.Errorf("failed to build swap tx: %w", err)
	}
	l.Debug("swap route found, tx=", base64.StdEncoding.EncodeToString(swapTx))

	txHash, err := network.SignerSwap.SignAndBroadcast(ctx, fromChain, *pol, swapTx)
	if err != nil {
		// Record failed swap transaction
		c.metrics.RecordSwapTransactionWithFallback(fromAssetTyped.String(), toAsset, fromChain.String(), toChainTyped.String(), false)
		return fmt.Errorf("failed to sign & broadcast swap: %w", err)
	}

	// Record successful swap transaction
	c.metrics.RecordSwapTransactionWithFallback(fromAssetTyped.String(), toAsset, fromChain.String(), toChainTyped.String(), true)
	l.WithField("txHash", txHash).Info("tx signed & broadcasted")
	return nil
}

func (c *Consumer) handleEvmSend(
	ctx context.Context,
	pol *types.PluginPolicy,
	fromChain common.Chain,
	fromAsset string,
	recipients []Recipient,
) error {
	if len(recipients) == 0 {
		return fmt.Errorf("recipients list is empty")
	}

	// Pre-compute shared values (once, outside loop)
	fromAsset = util.IfEmptyElse(fromAsset, evmsdk.ZeroAddress.String())
	fromAssetTyped := ecommon.HexToAddress(fromAsset)

	fromAddressTyped, err := c.evmPubToAddress(fromChain, pol.PublicKey, string(pol.PluginID))
	if err != nil {
		return fmt.Errorf("failed to parse policy PublicKey: %w", err)
	}

	network, err := c.evm.Get(fromChain)
	if err != nil {
		return fmt.Errorf("failed to get network: %w", err)
	}

	isNative := fromAssetTyped == evmsdk.ZeroAddress

	c.logger.WithFields(logrus.Fields{
		"operation":       "send",
		"policyID":        pol.ID.String(),
		"chain":           fromChain.String(),
		"fromAddress":     fromAddressTyped.String(),
		"asset":           fromAssetTyped.String(),
		"isNative":        isNative,
		"recipientCount":  len(recipients),
	}).Info("processing EVM send for multiple recipients")

	// Process each recipient sequentially
	for i, recipient := range recipients {
		err := c.sendToEvmRecipient(
			ctx,
			pol,
			network,
			fromChain,
			fromAssetTyped,
			fromAddressTyped,
			isNative,
			recipient,
			i,
		)
		if err != nil {
			c.logger.WithFields(logrus.Fields{
				"recipientIndex": i,
				"toAddress":      recipient.ToAddress,
				"amount":         recipient.Amount,
			}).WithError(err).Error("failed to send to recipient, stopping")
			return fmt.Errorf("failed at recipient[%d] %s: %w", i, recipient.ToAddress, err)
		}
	}

	c.logger.WithField("recipientCount", len(recipients)).Info("all EVM sends completed successfully")
	return nil
}

// sendToEvmRecipient sends to a single recipient. Extracted for clarity.
func (c *Consumer) sendToEvmRecipient(
	ctx context.Context,
	pol *types.PluginPolicy,
	network *evm.Network,
	fromChain common.Chain,
	fromAssetTyped ecommon.Address,
	fromAddressTyped ecommon.Address,
	isNative bool,
	recipient Recipient,
	recipientIndex int,
) error {
	fromAmountTyped, ok := new(big.Int).SetString(recipient.Amount, 10)
	if !ok {
		return fmt.Errorf("failed to parse amount %q as integer", recipient.Amount)
	}

	toAddressTyped := ecommon.HexToAddress(recipient.ToAddress)

	l := c.logger.WithFields(logrus.Fields{
		"recipientIndex": recipientIndex,
		"toAddress":      toAddressTyped.String(),
		"amount":         fromAmountTyped.String(),
	})

	var sendTx []byte
	var err error

	nonceOffset := uint64(recipientIndex)

	if isNative {
		l.Debug("building native token transfer")
		sendTx, err = network.Send.BuildNativeTransfer(ctx, fromAddressTyped, toAddressTyped, fromAmountTyped, nonceOffset)
		if err != nil {
			return fmt.Errorf("failed to build native transfer: %w", err)
		}
	} else {
		l.Debug("building ERC20 token transfer")
		sendTx, err = network.Send.BuildERC20Transfer(
			ctx,
			fromAssetTyped,
			fromAddressTyped,
			toAddressTyped,
			fromAmountTyped,
			nonceOffset,
		)
		if err != nil {
			return fmt.Errorf("failed to build ERC20 transfer: %w", err)
		}
	}

	txHash, err := network.SignerSend.SignAndBroadcast(ctx, fromChain, *pol, sendTx)
	if err != nil {
		return fmt.Errorf("failed to sign & broadcast: %w", err)
	}

	l.WithField("txHash", txHash).Info("send tx broadcasted successfully")
	return nil
}

func (c *Consumer) convertAmountToBaseUnits(ctx context.Context, chain common.Chain, token string, amount string) (string, error) {
	// Get decimals for the token
	decimals, err := c.getTokenDecimals(ctx, chain, token)
	if err != nil {
		return "", fmt.Errorf("failed to get token decimals: %w", err)
	}

	// Convert to base units
	baseUnits, err := util.ToBaseUnits(amount, decimals)
	if err != nil {
		return "", fmt.Errorf("failed to convert amount to base units: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"chain":       chain.String(),
		"token":       token,
		"humanAmount": amount,
		"baseUnits":   baseUnits.String(),
		"decimals":    decimals,
	}).Debug("converted amount to base units")

	return baseUnits.String(), nil
}

// getTokenDecimals returns the decimals for a token on a given chain
func (c *Consumer) getTokenDecimals(ctx context.Context, chain common.Chain, token string) (int, error) {
	// Check if it's a native token
	if util.IsNativeToken(token) {
		return util.GetNativeDecimals(chain)
	}

	// For EVM chains, fetch decimals from the contract
	if chain.IsEvm() {
		network, err := c.evm.Get(chain)
		if err != nil {
			return 0, fmt.Errorf("failed to get EVM network: %w", err)
		}

		tokenAddr := ecommon.HexToAddress(token)
		decimals, err := network.Decimals.GetDecimals(ctx, tokenAddr)
		if err != nil {
			return 0, fmt.Errorf("failed to get ERC20 decimals: %w", err)
		}

		return int(decimals), nil
	}

	// For non-EVM chains with tokens, return native decimals as fallback
	// (most non-EVM tokens use the same decimals as native)
	return util.GetNativeDecimals(chain)
}
