package recurring

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	ecommon "github.com/ethereum/go-ethereum/common"
	solanasdk "github.com/gagliardetto/solana-go"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/app-recurring/internal/btc"
	"github.com/vultisig/app-recurring/internal/cosmos"
	"github.com/vultisig/app-recurring/internal/dash"
	"github.com/vultisig/app-recurring/internal/evm"
	"github.com/vultisig/app-recurring/internal/maya"
	"github.com/vultisig/app-recurring/internal/metrics"
	"github.com/vultisig/app-recurring/internal/rune"
	"github.com/vultisig/app-recurring/internal/solana"
	"github.com/vultisig/app-recurring/internal/tron"
	"github.com/vultisig/app-recurring/internal/util"
	"github.com/vultisig/app-recurring/internal/utxo"
	utxoaddress "github.com/vultisig/app-recurring/internal/utxo/address"
	"github.com/vultisig/app-recurring/internal/xrp"
	"github.com/vultisig/app-recurring/internal/zcash"
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
	fromAsset       = "from"
	fromAmount      = "fromAmount"
	toAsset         = "to"
	routePreference = "routePreference"
)

// Recipient holds the parsed data for a single send recipient
type Recipient struct {
	ToAddress string
	Amount    string
}

// parsedConfig holds the parsed configuration from either send or swap schema
type parsedConfig struct {
	FromChain       common.Chain
	FromChainStr    string
	FromAsset       string
	FromAddress     string
	FromAmount      string
	ToChainStr      string
	ToAsset         string
	ToAddress       string
	ToAssetMap      map[string]any
	IsSend          bool
	RoutePreference string

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

	routePref := util.GetStr(cfg, routePreference)

	return &parsedConfig{
		FromChain:       fromChain,
		FromChainStr:    fromChainStr,
		FromAsset:       fromAssetToken,
		FromAddress:     fromAddressStr,
		FromAmount:      fromAmountStr,
		ToChainStr:      toChainStr,
		ToAsset:         toAssetToken,
		ToAddress:       toAddressStr,
		ToAssetMap:      toAssetMap,
		IsSend:          isSend,
		RoutePreference: routePref,
	}, nil
}

type Consumer struct {
	logger      *logrus.Logger
	policy      policy.Service
	evm         *evm.Manager
	btc         *btc.Network
	ltc         *utxo.Network
	doge        *utxo.Network
	bch         *utxo.Network
	dash        *dash.Network
	xrp         *xrp.Network
	solana      *solana.Network
	zcash       *zcash.Network
	cosmos      *cosmos.Network
	maya        *maya.Network
	tron        *tron.Network
	rune        *rune.Network
	vault       vault.Storage
	vaultSecret string
	metrics     *metrics.WorkerMetrics
}

func NewConsumer(
	logger *logrus.Logger,
	policy policy.Service,
	evm *evm.Manager,
	btc *btc.Network,
	ltc *utxo.Network,
	doge *utxo.Network,
	bch *utxo.Network,
	dash *dash.Network,
	solana *solana.Network,
	xrp *xrp.Network,
	zcash *zcash.Network,
	cosmos *cosmos.Network,
	maya *maya.Network,
	tron *tron.Network,
	runeNetwork *rune.Network,
	vault vault.Storage,
	vaultSecret string,
) *Consumer {
	return &Consumer{
		logger:      logger.WithField("pkg", "recurring.Consumer").Logger,
		policy:      policy,
		evm:         evm,
		btc:         btc,
		ltc:         ltc,
		doge:        doge,
		bch:         bch,
		dash:        dash,
		xrp:         xrp,
		solana:      solana,
		zcash:       zcash,
		cosmos:      cosmos,
		maya:        maya,
		tron:        tron,
		rune:        runeNetwork,
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

		if pcfg.FromChain == common.Litecoin {
			er := c.handleLtcSend(ctx, pol, pcfg.Recipients)
			if er != nil {
				return fmt.Errorf("failed to handle LTC send: %w", er)
			}
			return nil
		}

		if pcfg.FromChain == common.Dogecoin {
			er := c.handleDogeSend(ctx, pol, pcfg.Recipients)
			if er != nil {
				return fmt.Errorf("failed to handle DOGE send: %w", er)
			}
			return nil
		}

		if pcfg.FromChain == common.BitcoinCash {
			er := c.handleBchSend(ctx, pol, pcfg.Recipients)
			if er != nil {
				return fmt.Errorf("failed to handle BCH send: %w", er)
			}
			return nil
		}

		if pcfg.FromChain == common.Dash {
			er := c.handleDashSend(ctx, pol, pcfg.Recipients)
			if er != nil {
				return fmt.Errorf("failed to handle DASH send: %w", er)
			}
			return nil
		}

		if pcfg.FromChain == common.GaiaChain {
			er := c.handleCosmosSend(ctx, pol, pcfg.Recipients)
			if er != nil {
				return fmt.Errorf("failed to handle Cosmos send: %w", er)
			}
			return nil
		}

		if pcfg.FromChain == common.MayaChain {
			er := c.handleMayaSend(ctx, pol, pcfg.Recipients)
			if er != nil {
				return fmt.Errorf("failed to handle Maya send: %w", er)
			}
			return nil
		}

		if pcfg.FromChain == common.Tron {
			er := c.handleTronSend(ctx, pol, pcfg.Recipients)
			if er != nil {
				return fmt.Errorf("failed to handle Tron send: %w", er)
			}
			return nil
		}

		if pcfg.FromChain == common.THORChain {
			er := c.handleRuneSend(ctx, pol, pcfg.Recipients)
			if er != nil {
				return fmt.Errorf("failed to handle RUNE send: %w", er)
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

	if pcfg.FromChain == common.Litecoin {
		er := c.handleLtcSwap(ctx, pol, pcfg.ToAssetMap, pcfg.FromAmount, pcfg.ToAsset, pcfg.ToAddress)
		if er != nil {
			return fmt.Errorf("failed to handle LTC swap: %w", er)
		}
		return nil
	}

	if pcfg.FromChain == common.Dogecoin {
		er := c.handleDogeSwap(ctx, pol, pcfg.ToAssetMap, pcfg.FromAmount, pcfg.ToAsset, pcfg.ToAddress)
		if er != nil {
			return fmt.Errorf("failed to handle DOGE swap: %w", er)
		}
		return nil
	}

	if pcfg.FromChain == common.BitcoinCash {
		er := c.handleBchSwap(ctx, pol, pcfg.ToAssetMap, pcfg.FromAmount, pcfg.ToAsset, pcfg.ToAddress)
		if er != nil {
			return fmt.Errorf("failed to handle BCH swap: %w", er)
		}
		return nil
	}

	if pcfg.FromChain == common.Dash {
		er := c.handleDashSwap(ctx, pol, pcfg.ToAssetMap, pcfg.FromAmount, pcfg.ToAsset, pcfg.ToAddress)
		if er != nil {
			return fmt.Errorf("failed to handle DASH swap: %w", er)
		}
		return nil
	}

	if pcfg.FromChain == common.GaiaChain {
		er := c.handleCosmosSwap(ctx, pol, pcfg.ToAssetMap, pcfg.FromAmount, pcfg.ToAsset, pcfg.ToAddress)
		if er != nil {
			return fmt.Errorf("failed to handle Cosmos swap: %w", er)
		}
		return nil
	}

	if pcfg.FromChain == common.MayaChain {
		er := c.handleMayaSwap(ctx, pol, pcfg.ToAssetMap, pcfg.FromAmount, pcfg.ToAsset, pcfg.ToAddress)
		if er != nil {
			return fmt.Errorf("failed to handle Maya swap: %w", er)
		}
		return nil
	}

	if pcfg.FromChain == common.Tron {
		er := c.handleTronSwap(ctx, pol, pcfg.ToAssetMap, pcfg.FromAsset, pcfg.FromAmount, pcfg.ToAsset, pcfg.ToAddress)
		if er != nil {
			return fmt.Errorf("failed to handle Tron swap: %w", er)
		}
		return nil
	}

	if pcfg.FromChain == common.THORChain {
		er := c.handleRuneSwap(ctx, pol, pcfg.ToAssetMap, pcfg.FromAmount, pcfg.ToAsset, pcfg.ToAddress)
		if er != nil {
			return fmt.Errorf("failed to handle RUNE swap: %w", er)
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
		pcfg.RoutePreference,
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

	if err != nil {
		if isInsufficientBalanceError(err) {
			c.logger.WithFields(logrus.Fields{
				"policyID": policyID,
				"error":    err.Error(),
			}).Warn("skipping execution: insufficient balance (no retry until next scheduled run)")
			if c.metrics != nil {
				c.metrics.RecordPolicyExecution(policyID, false, duration)
			}
			return asynq.SkipRetry
		}

		c.logger.WithError(err).Error("failed to handle trigger")
		if c.metrics != nil {
			c.metrics.RecordPolicyExecution(policyID, false, duration)
			c.metrics.RecordError(metrics.ErrorTypeExecution)
		}
		return asynq.SkipRetry
	}
	if c.metrics != nil {
		c.metrics.RecordPolicyExecution(policyID, true, duration)
	}
	return nil
}

func isInsufficientBalanceError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "insufficient balance") ||
		strings.Contains(errStr, "insufficient funds") ||
		strings.Contains(errStr, "not enough balance")
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

func (c *Consumer) btcPubToAddress(rootPub string, pluginID string) (utxoaddress.UTXOAddress, *btcutil.AddressPubKey, error) {
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

	btcAddr, err := utxoaddress.NewBTCAddress(addr)
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

func (c *Consumer) handleEvmSwap(
	ctx context.Context,
	pol *types.PluginPolicy,
	recipe *rtypes.Policy,
	trigger scheduler.Scheduler,
	toAssetMap map[string]any,
	fromChain common.Chain,
	fromAsset, fromAmount, toAsset, toAddress string,
	routePreference string,
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

	// Check sufficient balance before signing
	balance, err := network.Balance.GetERC20Balance(ctx, fromAssetTyped, fromAddressTyped)
	if err != nil {
		return fmt.Errorf("failed to get balance: %w", err)
	}
	if balance.Cmp(fromAmountTyped) < 0 {
		return fmt.Errorf("insufficient balance: have %s, need %s", balance.String(), fromAmountTyped.String())
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
		routePreference,
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

	// Check sufficient balance before signing
	balance, err := network.Balance.GetERC20Balance(ctx, fromAssetTyped, fromAddressTyped)
	if err != nil {
		return fmt.Errorf("failed to get balance: %w", err)
	}
	if balance.Cmp(fromAmountTyped) < 0 {
		return fmt.Errorf("insufficient balance: have %s, need %s", balance.String(), fromAmountTyped.String())
	}

	toAddressTyped := ecommon.HexToAddress(recipient.ToAddress)

	l := c.logger.WithFields(logrus.Fields{
		"recipientIndex": recipientIndex,
		"toAddress":      toAddressTyped.String(),
		"amount":         fromAmountTyped.String(),
	})

	var sendTx []byte

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

// ============================================================================
// Litecoin (LTC) handlers
// ============================================================================

func (c *Consumer) ltcPubToAddress(rootPub string, pluginID string) (utxoaddress.UTXOAddress, []byte, error) {
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

	ltcAddr, err := utxoaddress.NewLTCAddress(addr)
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

func (c *Consumer) dogePubToAddress(rootPub string, pluginID string) (utxoaddress.UTXOAddress, []byte, error) {
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

	dogeAddr, err := utxoaddress.NewDOGEAddress(addr)
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

func (c *Consumer) bchPubToAddress(rootPub string, pluginID string) (utxoaddress.UTXOAddress, []byte, error) {
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

	bchAddr, err := utxoaddress.NewBCHAddress(addr)
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
		amountRune, err := parseUint64(recipient.Amount)
		if err != nil {
			return fmt.Errorf("failed to parse amount for recipient[%d]: %w", i, err)
		}

		txHash, err := c.rune.SendPayment(ctx, *pol, fromAddressStr, recipient.ToAddress, amountRune, childPubKey)
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
	fromAsset, fromAmount, toAsset, toAddress string,
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
		AssetID: fromAsset,
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
		"fromAsset":   fromAsset,
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
