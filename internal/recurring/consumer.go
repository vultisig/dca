package recurring

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/dca/internal/btc"
	"github.com/vultisig/dca/internal/cosmos"
	"github.com/vultisig/dca/internal/dash"
	"github.com/vultisig/dca/internal/evm"
	"github.com/vultisig/dca/internal/maya"
	"github.com/vultisig/dca/internal/metrics"
	"github.com/vultisig/dca/internal/rune"
	"github.com/vultisig/dca/internal/solana"
	"github.com/vultisig/dca/internal/tron"
	"github.com/vultisig/dca/internal/util"
	"github.com/vultisig/dca/internal/utxo"
	"github.com/vultisig/dca/internal/xrp"
	"github.com/vultisig/dca/internal/zcash"
	"github.com/vultisig/verifier/plugin/policy"
	"github.com/vultisig/verifier/plugin/scheduler"
	"github.com/vultisig/verifier/vault"
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
	runeNet *rune.Network,
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
		rune:        runeNet,
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

		if pcfg.FromChain == common.THORChain {
			er := c.handleRuneSend(ctx, pol, pcfg.Recipients)
			if er != nil {
				return fmt.Errorf("failed to handle RUNE send: %w", er)
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

	if pcfg.FromChain == common.THORChain {
		er := c.handleRuneSwap(ctx, pol, pcfg.ToAssetMap, pcfg.FromAmount, pcfg.ToAsset, pcfg.ToAddress)
		if er != nil {
			return fmt.Errorf("failed to handle RUNE swap: %w", er)
		}
		return nil
	}

	if pcfg.FromChain == common.Tron {
		er := c.handleTronSwap(ctx, pol, pcfg.ToAssetMap, pcfg.FromAmount, pcfg.ToAsset, pcfg.ToAddress)
		if er != nil {
			return fmt.Errorf("failed to handle Tron swap: %w", er)
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
