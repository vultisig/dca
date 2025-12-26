package recurring

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	ecommon "github.com/ethereum/go-ethereum/common"
	solanasdk "github.com/gagliardetto/solana-go"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/dca/internal/btc"
	"github.com/vultisig/dca/internal/evm"
	"github.com/vultisig/dca/internal/metrics"
	"github.com/vultisig/dca/internal/solana"
	"github.com/vultisig/dca/internal/util"
	"github.com/vultisig/dca/internal/xrp"
	"github.com/vultisig/dca/internal/zcash"
	"github.com/vultisig/mobile-tss-lib/tss"
	"github.com/vultisig/recipes/metarule"
	"github.com/vultisig/recipes/resolver"
	btcsdk "github.com/vultisig/recipes/sdk/btc"
	evmsdk "github.com/vultisig/recipes/sdk/evm"
	rtypes "github.com/vultisig/recipes/types"
	"github.com/vultisig/verifier/plugin/policy"
	"github.com/vultisig/verifier/plugin/scheduler"
	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/rpc"
	"github.com/vultisig/verifier/types"
	"github.com/vultisig/verifier/vault"
	"github.com/vultisig/vultisig-go/address"
	"github.com/vultisig/vultisig-go/common"
)

const (
	fromAsset  = "from"
	fromAmount = "fromAmount"
	toAsset    = "to"
)

// Recipient holds the parsed data for a single send recipient
type Recipient struct {
	ToAddress string
	Amount    string
}

// parsedConfig holds the parsed configuration from either send or swap schema
type parsedConfig struct {
	FromChain    common.Chain
	FromChainStr string
	FromAsset    string
	FromAddress  string
	FromAmount   string
	ToChainStr   string
	ToAsset      string
	ToAddress    string
	ToAssetMap   map[string]any
	IsSend       bool

	// Recipients holds all parsed recipients for send operations.
	// Chain handlers can use this for multi-recipient support,
	// or use the single-recipient fields above for backward compatibility.
	Recipients []Recipient
}

// parseSendConfig parses send schema with top-level asset and recipients array.
func parseSendConfig(cfg map[string]any) (*parsedConfig, error) {
	// Parse top-level asset (shared by all recipients)
	assetMap, ok := cfg["asset"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("'asset' must be an object")
	}

	chainStr := util.GetStr(assetMap, "chain")
	if chainStr == "" {
		return nil, fmt.Errorf("'asset.chain' could not be empty")
	}

	chain, err := common.FromString(chainStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse asset.chain: %w", err)
	}

	token := util.GetStr(assetMap, "token")

	// asset.address = sender's address (fromAddress)
	fromAddr := util.GetStr(assetMap, "address")
	if fromAddr == "" {
		return nil, fmt.Errorf("'asset.address' (sender address) could not be empty")
	}

	// Parse recipients array
	recipientsList, ok := cfg["recipients"].([]any)
	if !ok || len(recipientsList) == 0 {
		return nil, fmt.Errorf("'recipients' must be a non-empty array")
	}

	var recipients []Recipient
	for i, recipientItem := range recipientsList {
		recipient, ok := recipientItem.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("'recipients[%d]' must be an object", i)
		}

		toAddr := util.GetStr(recipient, "toAddress")
		if toAddr == "" {
			return nil, fmt.Errorf("'recipients[%d].toAddress' could not be empty", i)
		}

		amount := util.GetStr(recipient, "amount")
		if amount == "" {
			return nil, fmt.Errorf("'recipients[%d].amount' could not be empty", i)
		}

		recipients = append(recipients, Recipient{
			ToAddress: toAddr,
			Amount:    amount,
		})
	}

	// Use first recipient for backward-compatible single-recipient fields
	firstRecipient := recipients[0]

	return &parsedConfig{
		FromChain:    chain,
		FromChainStr: chainStr,
		FromAsset:    token,
		FromAddress:  fromAddr,
		FromAmount:   firstRecipient.Amount,
		ToChainStr:   chainStr,
		ToAsset:      token,
		ToAddress:    firstRecipient.ToAddress,
		ToAssetMap: map[string]any{
			"chain":   chainStr,
			"token":   token,
			"address": firstRecipient.ToAddress,
		},
		IsSend:     true,
		Recipients: recipients,
	}, nil
}

// parseSwapConfig parses swap schema: from, to, fromAmount
func parseSwapConfig(cfg map[string]any) (*parsedConfig, error) {
	fromAmountStr, ok := cfg[fromAmount].(string)
	if !ok {
		return nil, fmt.Errorf("failed to get fromAmount")
	}

	fromAssetMap, ok := cfg[fromAsset].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("'from' must be an object")
	}

	toAssetMap, ok := cfg[toAsset].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("'to' must be an object")
	}

	fromChainStr, ok := fromAssetMap["chain"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to get from.chain")
	}

	fromChain, err := common.FromString(fromChainStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse from.chain: %w", err)
	}

	toChainStr, ok := toAssetMap["chain"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to get to.chain")
	}

	fromAddressStr, ok := fromAssetMap["address"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to get from.address")
	}

	toAddressStr, ok := toAssetMap["address"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to get to.address")
	}

	fromAssetToken := util.GetStr(fromAssetMap, "token")
	toAssetToken := util.GetStr(toAssetMap, "token")

	isSend := fromChainStr == toChainStr && fromAssetToken == toAssetToken && fromAddressStr != toAddressStr

	return &parsedConfig{
		FromChain:    fromChain,
		FromChainStr: fromChainStr,
		FromAsset:    fromAssetToken,
		FromAddress:  fromAddressStr,
		FromAmount:   fromAmountStr,
		ToChainStr:   toChainStr,
		ToAsset:      toAssetToken,
		ToAddress:    toAddressStr,
		ToAssetMap:   toAssetMap,
		IsSend:       isSend,
	}, nil
}

type Consumer struct {
	logger      *logrus.Logger
	policy      policy.Service
	evm         *evm.Manager
	btc         *btc.Network
	xrp         *xrp.Network
	solana      *solana.Network
	zcash       *zcash.Network
	vault       vault.Storage
	vaultSecret string
	metrics     *metrics.WorkerMetrics
}

func NewConsumer(
	logger *logrus.Logger,
	policy policy.Service,
	evm *evm.Manager,
	btc *btc.Network,
	solana *solana.Network,
	xrp *xrp.Network,
	zcash *zcash.Network,
	vault vault.Storage,
	vaultSecret string,
) *Consumer {
	return &Consumer{
		logger:      logger.WithField("pkg", "recurring.Consumer").Logger,
		policy:      policy,
		evm:         evm,
		btc:         btc,
		xrp:         xrp,
		solana:      solana,
		zcash:       zcash,
		vault:       vault,
		vaultSecret: vaultSecret,
		metrics:     metrics.NewWorkerMetrics(),
	}
}

func (c *Consumer) handle(ctx context.Context, t *asynq.Task) error {
	var trigger scheduler.Scheduler
	if err := json.Unmarshal(t.Payload(), &trigger); err != nil {
		return fmt.Errorf("failed to unmarshal trigger payload: %w", err)
	}

	pol, err := c.policy.GetPluginPolicy(ctx, trigger.PolicyID)
	if err != nil {
		return fmt.Errorf("failed to get policy: %w", err)
	}

	recipe, err := pol.GetRecipe()
	if err != nil {
		return fmt.Errorf("failed to get recipe: %w", err)
	}

	cfg := recipe.GetConfiguration().AsMap()

	// Detect config schema: send schema has "recipients", swap schema has "to"
	var pcfg *parsedConfig
	if _, hasRecipients := cfg["recipients"].([]any); hasRecipients {
		pcfg, err = parseSendConfig(cfg)
	} else {
		pcfg, err = parseSwapConfig(cfg)
	}
	if err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	if pcfg.IsSend {
		c.logger.WithFields(logrus.Fields{
			"policyID":    pol.ID.String(),
			"operation":   "send",
			"chain":       pcfg.FromChainStr,
			"asset":       pcfg.FromAsset,
			"fromAddress": pcfg.FromAddress,
			"toAddress":   pcfg.ToAddress,
		}).Info("detected send operation")

		if pcfg.FromChain.IsEvm() {
			er := c.handleEvmSend(ctx, pol, pcfg.FromChain, pcfg.FromAsset, pcfg.Recipients)
			if er != nil {
				return fmt.Errorf("failed to handle EVM send: %w", er)
			}
			return nil
		}

		if pcfg.FromChain == common.XRP {
			er := c.handleXrpSend(ctx, pol, pcfg.FromAsset, pcfg.Recipients)
			if er != nil {
				return fmt.Errorf("failed to handle XRP send: %w", er)
			}
			return nil
		}

		if pcfg.FromChain == common.Solana {
			er := c.handleSolanaSend(ctx, pol, pcfg.FromAsset, pcfg.Recipients)
			if er != nil {
				return fmt.Errorf("failed to handle Solana send: %w", er)
			}
			return nil
		}

		if pcfg.FromChain == common.Bitcoin {
			er := c.handleBtcSend(ctx, pol, pcfg.Recipients)
			if er != nil {
				return fmt.Errorf("failed to handle BTC send: %w", er)
			}
			return nil
		}

		if pcfg.FromChain == common.Zcash {
			er := c.handleZcashSend(ctx, pol, pcfg.Recipients)
			if er != nil {
				return fmt.Errorf("failed to handle Zcash send: %w", er)
			}
			return nil
		}

		c.logger.WithFields(logrus.Fields{
			"chain":     pcfg.FromChainStr,
			"operation": "send",
		}).Warn("send operation not yet supported for this chain")
		return fmt.Errorf("send operation not yet supported for chain: %s", pcfg.FromChain.String())
	}

	if pcfg.FromChain == common.Bitcoin {
		er := c.handleBtcSwap(ctx, pol, pcfg.ToAssetMap, pcfg.FromAmount, pcfg.ToAsset, pcfg.ToAddress)
		if er != nil {
			return fmt.Errorf("failed to handle BTC swap: %w", er)
		}
		return nil
	}

	if pcfg.FromChain == common.XRP {
		er := c.handleXrpSwap(ctx, pol, pcfg.ToAssetMap, pcfg.FromAmount, pcfg.ToAsset, pcfg.ToAddress)
		if er != nil {
			return fmt.Errorf("failed to handle XRP swap: %w", er)
		}
		return nil
	}

	if pcfg.FromChain == common.Solana {
		er := c.handleSolanaSwap(ctx, pol, pcfg.ToAssetMap, pcfg.FromAmount, pcfg.FromAsset, pcfg.ToAsset, pcfg.ToAddress)
		if er != nil {
			return fmt.Errorf("failed to handle Solana swap: %w", er)
		}
		return nil
	}

	if pcfg.FromChain == common.Zcash {
		er := c.handleZcashSwap(ctx, pol, pcfg.ToAssetMap, pcfg.FromAmount, pcfg.ToAsset, pcfg.ToAddress)
		if er != nil {
			return fmt.Errorf("failed to handle Zcash swap: %w", er)
		}
		return nil
	}

	err = c.handleEvmSwap(
		ctx,
		pol,
		recipe,
		trigger,
		pcfg.ToAssetMap,
		pcfg.FromChain,
		pcfg.FromAsset,
		pcfg.FromAmount,
		pcfg.ToAsset,
		pcfg.ToAddress,
	)
	if err != nil {
		return fmt.Errorf("failed to handle EVM swap: %w", err)
	}
	return nil
}

func (c *Consumer) Handle(_ context.Context, t *asynq.Task) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	start := time.Now()
	err := c.handle(ctx, t)
	duration := time.Since(start)

	// Extract policy ID for metrics
	var trigger scheduler.Scheduler
	policyID := "unknown"
	if unmarshalErr := json.Unmarshal(t.Payload(), &trigger); unmarshalErr == nil {
		policyID = trigger.PolicyID.String()
	}

	// Record policy execution metrics
	success := err == nil
	if c.metrics != nil {
		c.metrics.RecordPolicyExecution(policyID, success, duration)
	}

	if err != nil {
		c.logger.WithError(err).Error("failed to handle trigger")
		if c.metrics != nil {
			c.metrics.RecordError(metrics.ErrorTypeExecution)
		}
		return asynq.SkipRetry
	}
	return nil
}

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
	if len(recipients) > 1 {
		c.logger.WithField("recipientCount", len(recipients)).Warn("multi-recipient send not yet supported, only handling first recipient")
	}

	// Extract first recipient for now
	recipient := recipients[0]
	fromAmount := recipient.Amount
	toAddress := recipient.ToAddress

	fromAddressTyped, err := c.solanaPubToAddress(pol.PublicKey, string(pol.PluginID))
	if err != nil {
		return fmt.Errorf("failed to get Solana address from policy PublicKey: %w", err)
	}

	fromAmountTyped, err := parseUint64(fromAmount)
	if err != nil {
		return fmt.Errorf("failed to parse fromAmount: %w", err)
	}

	fromPubKey, err := solanasdk.PublicKeyFromBase58(fromAddressTyped)
	if err != nil {
		return fmt.Errorf("failed to parse from address: %w", err)
	}

	toPubKey, err := solanasdk.PublicKeyFromBase58(toAddress)
	if err != nil {
		return fmt.Errorf("failed to parse to address: %w", err)
	}

	isNative := fromAsset == ""

	l := c.logger.WithFields(logrus.Fields{
		"operation":   "send",
		"policyID":    pol.ID.String(),
		"chain":       "solana",
		"fromAddress": fromAddressTyped,
		"toAddress":   toAddress,
		"asset":       fromAsset,
		"amount":      fromAmountTyped,
		"isNative":    isNative,
	})

	l.Info("handling Solana send")

	txHash, err := c.solana.Send(ctx, *pol, fromPubKey, toPubKey, fromAsset, fromAmountTyped)
	if err != nil {
		l.WithError(err).Error("failed to execute Solana send")
		return fmt.Errorf("failed to execute Solana send: %w", err)
	}

	l.WithField("txHash", txHash).Info("Solana send executed successfully")
	return nil
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

	spender, err := findSpender(fromChain, recipe.GetRules())
	if err != nil {
		return fmt.Errorf("failed to find approve rule: %w", err)
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

	swapTx, err := network.Swap.FindBestAmountOut(
		ctx,
		evm.From{
			Amount:  fromAmountTyped,
			Chain:   fromChain,
			AssetID: fromAssetTyped,
			Address: fromAddressTyped,
		},
		evm.To{
			Chain:   toChainTyped,
			AssetID: toAsset,
			Address: toAddress,
		},
	)
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

func findSpender(chain common.Chain, rawRules []*rtypes.Rule) (ecommon.Address, error) {
	for _, rawRule := range rawRules {
		rules, err := metarule.NewMetaRule().TryFormat(rawRule)
		if err != nil {
			return ecommon.Address{}, fmt.Errorf("failed to parse rule: %w", err)
		}

		for _, rule := range rules {
			if rule.GetTarget().GetTargetType() == rtypes.TargetType_TARGET_TYPE_MAGIC_CONSTANT {
				c := rule.GetTarget().GetMagicConstant()

				resolve, er := resolver.NewMagicConstantRegistry().GetResolver(c)
				if er != nil {
					return ecommon.Address{}, fmt.Errorf(
						"failed to get resolver (%s): %w",
						rule.GetTarget().GetMagicConstant(),
						er,
					)
				}

				router, _, er := resolve.Resolve(c, chain.String(), "")
				if er != nil {
					return ecommon.Address{}, fmt.Errorf(
						"failed to resolve magic constant (%s): %w",
						rule.GetTarget().GetMagicConstant(),
						er,
					)
				}
				return ecommon.HexToAddress(router), nil
			}

			return ecommon.HexToAddress(rule.GetTarget().GetAddress()), nil
		}
	}
	return ecommon.Address{}, fmt.Errorf("rule not found")
}

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

// convertAmountToBaseUnits converts a human-readable amount to base units (e.g., "10" USDC -> "10000000").
// Always converts - if the amount is incorrect, the policy will reject the transaction.
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
