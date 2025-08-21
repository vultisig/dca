package dca

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"strings"
	"time"

	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/dca/internal/evm"
	"github.com/vultisig/mobile-tss-lib/tss"
	rtypes "github.com/vultisig/recipes/types"
	"github.com/vultisig/verifier/plugin/policy"
	"github.com/vultisig/verifier/plugin/scheduler"
	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/rpc"
	"github.com/vultisig/verifier/types"
	"github.com/vultisig/verifier/vault"
	"github.com/vultisig/vultisig-go/address"
	"github.com/vultisig/vultisig-go/common"
)

type Consumer struct {
	logger      *logrus.Logger
	policy      policy.Service
	evm         *evm.Manager
	vault       vault.Storage
	vaultSecret string
}

func NewConsumer(
	logger *logrus.Logger,
	policy policy.Service,
	evm *evm.Manager,
	vault vault.Storage,
	vaultSecret string,
) *Consumer {
	return &Consumer{
		logger:      logger.WithField("pkg", "dca.Consumer").Logger,
		policy:      policy,
		evm:         evm,
		vault:       vault,
		vaultSecret: vaultSecret,
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

	fromAssetStr, ok := cfg[fromAsset].(string)
	if !ok {
		return fmt.Errorf("failed to get fromAsset: %w", err)
	}
	fromAmountStr, ok := cfg[fromAmount].(string)
	if !ok {
		return fmt.Errorf("failed to get fromAmount: %w", err)
	}

	toAssetStr, ok := cfg[toAsset].(string)
	if !ok {
		return fmt.Errorf("failed to get toAsset: %w", err)
	}
	toAddressStr, ok := cfg[toAddress].(string)
	if !ok {
		return fmt.Errorf("failed to get toAddress: %w", err)
	}

	fromChainTyped, err := getChainFromCfg(cfg, fromChain)
	if err != nil {
		return fmt.Errorf("failed to get fromChain: %w", err)
	}
	fromAssetTyped := ecommon.HexToAddress(fromAssetStr)
	fromAddressTyped, err := c.evmPubToAddress(fromChainTyped, pol.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse policy PublicKey: %w", err)
	}
	fromAmountTyped, ok := new(big.Int).SetString(fromAmountStr, 10)
	if !ok {
		return fmt.Errorf("failed to parse fromAmountStr: %w", err)
	}

	toChainTyped, err := getChainFromCfg(cfg, toChain)
	if err != nil {
		return fmt.Errorf("failed to get toChain: %w", err)
	}
	toAssetTyped := ecommon.HexToAddress(toAssetStr)
	toAddressTyped := ecommon.HexToAddress(toAddressStr)

	network, err := c.evm.Get(fromChainTyped)
	if err != nil {
		return fmt.Errorf("failed to get network: %w", err)
	}

	approveRule, err := findApproveRule(fromChainTyped, recipe.GetRules())
	if err != nil {
		return fmt.Errorf("failed to find approve rule: %w", err)
	}

	router := ecommon.HexToAddress(approveRule.GetTarget().GetAddress())

	l := c.logger.WithFields(logrus.Fields{
		"policyID":   trigger.PolicyID.String(),
		"router":     router.String(),
		"fromChain":  fromChainTyped.String(),
		"fromAsset":  fromAssetTyped.String(),
		"fromAmount": fromAmountTyped.String(),
		"toChain":    toChainTyped.String(),
		"toAsset":    toAssetTyped.String(),
		"toAddress":  toAddressTyped.String(),
	})

	shouldApprove, approveTx, err := network.Approve.CheckAllowance(
		ctx,
		fromAssetTyped,
		fromAddressTyped,
		router,
		new(big.Int).SetUint64(math.MaxUint64),
	)
	if err != nil {
		return fmt.Errorf("failed to check allowance & build approve: %w", err)
	}
	if shouldApprove {
		l.Info("approve needed, wait mined")
		hash, er := network.Signer.SignAndBroadcast(ctx, *pol, approveTx)
		if er != nil {
			return fmt.Errorf("failed to sign & broadcast approve: %w", er)
		}
		st, er := network.Status.WaitMined(ctx, hash)
		if er != nil {
			return fmt.Errorf(
				"failed to wait approve: %s, hash=%s, chain=%s",
				st,
				hash,
				fromChainTyped.String(),
			)
		}
		if st != rpc.TxOnChainSuccess {
			return fmt.Errorf(
				"failed to land approve: %s, hash=%s, chain=%s",
				st,
				hash,
				fromChainTyped.String(),
			)
		}
	}

	swapTx, err := network.Swap.FindBestAmountOut(
		ctx,
		evm.Params{
			Chain:   fromChainTyped,
			AssetID: fromAssetTyped,
			Address: fromAddressTyped,
		},
		evm.Params{
			Chain:   toChainTyped,
			AssetID: toAssetTyped,
			Address: toAddressTyped,
		},
		fromAmountTyped,
	)
	if err != nil {
		return fmt.Errorf("failed to build swap tx: %w", err)
	}
	l.Info("swap route found")

	_, err = network.Signer.SignAndBroadcast(ctx, *pol, swapTx)
	if err != nil {
		return fmt.Errorf("failed to sign & broadcast swap: %w", err)
	}

	l.Info("tx signed & broadcasted")
	return nil
}

func (c *Consumer) Handle(ctx context.Context, t *asynq.Task) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	err := c.handle(ctx, t)
	if err != nil {
		c.logger.WithError(err).Error("failed to handle trigger")
		return asynq.SkipRetry
	}
	return nil
}

func (c *Consumer) evmPubToAddress(chain common.Chain, pub string) (ecommon.Address, error) {
	vaultContent, err := c.vault.GetVault(common.GetVaultBackupFilename(pub, string(types.PluginVultisigDCA_0000)))
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

func getChainFromCfg(cfg map[string]interface{}, field string) (common.Chain, error) {
	chainStr, ok := cfg[field].(string)
	if !ok {
		return 0, fmt.Errorf("failed to get chain: %s", field)
	}

	chainTyped, err := common.FromString(chainStr)
	if err != nil {
		return 0, fmt.Errorf("failed to parse chain: %w", err)
	}
	return chainTyped, nil
}

func findApproveRule(chain common.Chain, rules []*rtypes.Rule) (*rtypes.Rule, error) {
	for _, rule := range rules {
		if rule.GetResource() == fmt.Sprintf("%s.erc20.approve", strings.ToLower(chain.String())) {
			return rule, nil
		}
	}
	return nil, fmt.Errorf("approve rule not found")
}
