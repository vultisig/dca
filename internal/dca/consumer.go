package dca

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/dca/internal/btc"
	"github.com/vultisig/dca/internal/evm"
	"github.com/vultisig/dca/internal/solana"
	"github.com/vultisig/dca/internal/util"
	"github.com/vultisig/dca/internal/xrp"
	"github.com/vultisig/mobile-tss-lib/tss"
	"github.com/vultisig/recipes/metarule"
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
	btc         *btc.Network
	xrp         *xrp.Network
	solana      *solana.Network
	vault       vault.Storage
	vaultSecret string
}

func NewConsumer(
	logger *logrus.Logger,
	policy policy.Service,
	evm *evm.Manager,
	btc *btc.Network,
	solana *solana.Network,
	xrp *xrp.Network,
	vault vault.Storage,
	vaultSecret string,
) *Consumer {
	return &Consumer{
		logger:      logger.WithField("pkg", "dca.Consumer").Logger,
		policy:      policy,
		evm:         evm,
		btc:         btc,
		xrp:         xrp,
		solana:      solana,
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

	fromAmountStr, ok := cfg[fromAmount].(string)
	if !ok {
		return fmt.Errorf("failed to get fromAmount: %w", err)
	}

	fromAssetMap, ok := cfg[fromAsset].(map[string]any)
	if !ok {
		return fmt.Errorf("'fromAsset' must be an object")
	}

	toAssetMap, ok := cfg[toAsset].(map[string]any)
	if !ok {
		return fmt.Errorf("'toAsset' must be an object")
	}

	fromAssetTokenStr := util.GetStr(fromAssetMap, "token")
	toAssetTokenStr := util.GetStr(toAssetMap, "token")

	toAddressStr, ok := toAssetMap["address"].(string)
	if !ok {
		return fmt.Errorf("failed to get toAsset.address")
	}

	fromChainStr, ok := fromAssetMap["chain"].(string)
	if !ok {
		return fmt.Errorf("failed to get fromAsset.chain")
	}

	fromChainTyped, err := common.FromString(fromChainStr)
	if err != nil {
		return fmt.Errorf("failed to parse fromAsset.chain: %w", err)
	}

	if fromChainTyped == common.Bitcoin {
		er := c.handleBtcSwap(ctx, pol, toAssetMap, fromAmountStr, toAssetTokenStr, toAddressStr)
		if er != nil {
			return fmt.Errorf("failed to handle BTC swap: %w", er)
		}
		return nil
	}

	if fromChainTyped == common.XRP {
		er := c.handleXrpSwap(ctx, pol, toAssetMap, fromAmountStr, toAssetTokenStr, toAddressStr)
		if er != nil {
			return fmt.Errorf("failed to handle XRP swap: %w", er)
		}
		return nil
	}

	if fromChainTyped == common.Solana {
		er := c.handleSolanaSwap(ctx, pol, toAssetMap, fromAmountStr, fromAssetTokenStr, toAssetTokenStr, toAddressStr)
		if er != nil {
			return fmt.Errorf("failed to handle Solana swap: %w", er)
		}
		return nil
	}

	err = c.handleEvmSwap(
		ctx,
		pol,
		recipe,
		trigger,
		toAssetMap,
		fromChainTyped,
		fromAssetTokenStr,
		fromAmountStr,
		toAssetTokenStr,
		toAddressStr,
	)
	if err != nil {
		return fmt.Errorf("failed to handle EVM swap: %w", err)
	}
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

func (c *Consumer) btcPubToAddress(rootPub string) (btcutil.Address, *btcutil.AddressPubKey, error) {
	vaultContent, err := c.vault.GetVault(common.GetVaultBackupFilename(rootPub, string(types.PluginVultisigDCA_0000)))
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

func (c *Consumer) xrpPubToAddress(rootPub string) (string, string, error) {
	vaultContent, err := c.vault.GetVault(common.GetVaultBackupFilename(rootPub, string(types.PluginVultisigDCA_0000)))
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

func (c *Consumer) handleXrpSwap(
	ctx context.Context,
	pol *types.PluginPolicy,
	toAssetMap map[string]any,
	fromAmount, toAsset, toAddress string,
) error {
	fromAddressStr, childPubKey, err := c.xrpPubToAddress(pol.PublicKey)
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

	txHash, err := c.xrp.Swap(ctx, *pol, from, to)
	if err != nil {
		return fmt.Errorf("failed to execute XRP swap: %w", err)
	}

	c.logger.WithField("txHash", txHash).Info("XRP swap executed successfully")
	return nil
}

func parseUint64(s string) (uint64, error) {
	return strconv.ParseUint(s, 10, 64)
}

func (c *Consumer) solanaPubToAddress(rootPub string) (string, error) {
	vaultContent, err := c.vault.GetVault(common.GetVaultBackupFilename(rootPub, string(types.PluginVultisigDCA_0000)))
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
	fromAddressTyped, childPub, err := c.btcPubToAddress(pol.PublicKey)
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
		return fmt.Errorf("failed to execute BTC swap: %w", err)
	}

	c.logger.WithField("txHash", txHash).Info("BTC swap executed successfully")
	return nil
}

func (c *Consumer) handleSolanaSwap(
	ctx context.Context,
	pol *types.PluginPolicy,
	toAssetMap map[string]any,
	fromAmount, fromAsset, toAsset, toAddress string,
) error {
	fromAddressTyped, err := c.solanaPubToAddress(pol.PublicKey)
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
		return fmt.Errorf("failed to execute Solana swap: %w", err)
	}

	c.logger.WithField("txHash", txHash).Info("Solana swap executed successfully")
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
	fromAddressTyped, err := c.evmPubToAddress(fromChain, pol.PublicKey)
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
		new(big.Int).SetUint64(math.MaxUint64),
	)
	if err != nil {
		return fmt.Errorf("failed to check allowance & build approve: %w", err)
	}
	if shouldApprove {
		l.Info("approve needed, wait mined")

		hash, er := network.Signer.SignAndBroadcast(ctx, fromChain, *pol, approveTx)
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

	_, err = network.Signer.SignAndBroadcast(ctx, fromChain, *pol, swapTx)
	if err != nil {
		return fmt.Errorf("failed to sign & broadcast swap: %w", err)
	}

	l.Info("tx signed & broadcasted")
	return nil
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

func findSpender(_ common.Chain, rawRules []*rtypes.Rule) (ecommon.Address, error) {
	for _, rawRule := range rawRules {
		rules, err := metarule.NewMetaRule().TryFormat(rawRule)
		if err != nil {
			return ecommon.Address{}, fmt.Errorf("failed to parse rule: %w", err)
		}

		for _, rule := range rules {
			// TODO when ThorChain added, need to resolve MagicConst
			return ecommon.HexToAddress(rule.GetTarget().GetAddress()), nil
		}
	}
	return ecommon.Address{}, fmt.Errorf("rule not found")
}
