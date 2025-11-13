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
	solanasdk "github.com/gagliardetto/solana-go"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/dca/internal/btc"
	"github.com/vultisig/dca/internal/evm"
	"github.com/vultisig/dca/internal/solana"
	"github.com/vultisig/dca/internal/util"
	"github.com/vultisig/dca/internal/xrp"
	"github.com/vultisig/mobile-tss-lib/tss"
	"github.com/vultisig/recipes/metarule"
	"github.com/vultisig/recipes/resolver"
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

	toChainStr, ok := toAssetMap["chain"].(string)
	if !ok {
		return fmt.Errorf("failed to get toAsset.chain")
	}

	fromAddressStr, ok := fromAssetMap["address"].(string)
	if !ok {
		return fmt.Errorf("failed to get fromAsset.address")
	}

	isSend := fromChainStr == toChainStr && fromAssetTokenStr == toAssetTokenStr && fromAddressStr != toAddressStr

	if isSend {
		c.logger.WithFields(logrus.Fields{
			"policyID":    pol.ID.String(),
			"operation":   "send",
			"chain":       fromChainStr,
			"asset":       fromAssetTokenStr,
			"fromAddress": fromAddressStr,
			"toAddress":   toAddressStr,
		}).Info("detected send operation")

		if fromChainTyped.IsEvm() {
			er := c.handleEvmSend(ctx, pol, fromChainTyped, fromAssetTokenStr, fromAmountStr, toAddressStr)
			if er != nil {
				return fmt.Errorf("failed to handle EVM send: %w", er)
			}
			return nil
		}

		if fromChainTyped == common.XRP {
			er := c.handleXrpSend(ctx, pol, fromAssetTokenStr, fromAmountStr, toAddressStr)
			if er != nil {
				return fmt.Errorf("failed to handle XRP send: %w", er)
			}
			return nil
		}

		if fromChainTyped == common.Solana {
			er := c.handleSolanaSend(ctx, pol, fromAssetTokenStr, fromAmountStr, toAddressStr)
			if er != nil {
				return fmt.Errorf("failed to handle Solana send: %w", er)
			}
			return nil
		}

		if fromChainTyped == common.Bitcoin {
			er := c.handleBtcSend(ctx, pol, fromAmountStr, toAddressStr)
			if er != nil {
				return fmt.Errorf("failed to handle BTC send: %w", er)
			}
			return nil
		}

		c.logger.WithFields(logrus.Fields{
			"chain":     fromChainStr,
			"operation": "send",
		}).Warn("send operation not yet supported for this chain")
		return fmt.Errorf("send operation not yet supported for chain: %s", fromChainTyped.String())
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

func (c *Consumer) Handle(_ context.Context, t *asynq.Task) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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

func (c *Consumer) handleXrpSend(
	ctx context.Context,
	pol *types.PluginPolicy,
	fromAsset string,
	fromAmount string,
	toAddress string,
) error {
	// Validate that only native XRP is supported
	if fromAsset != "" {
		return fmt.Errorf("XRP send only supports native XRP, got token: %q", fromAsset)
	}

	fromAddressStr, childPubKey, err := c.xrpPubToAddress(pol.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to get XRP address from policy PublicKey: %w", err)
	}

	fromAmountDrops, err := parseUint64(fromAmount)
	if err != nil {
		return fmt.Errorf("failed to parse fromAmount: %w", err)
	}

	l := c.logger.WithFields(logrus.Fields{
		"operation":   "send",
		"policyID":    pol.ID.String(),
		"fromAddress": fromAddressStr,
		"toAddress":   toAddress,
		"amount":      fromAmountDrops,
		"asset":       fromAsset,
	})

	l.Info("building XRP payment transaction")
	sendTx, err := c.xrp.Send.BuildPayment(ctx, fromAddressStr, toAddress, fromAmountDrops, childPubKey)
	if err != nil {
		l.WithError(err).Error("failed to build XRP payment")
		return fmt.Errorf("failed to build XRP payment: %w", err)
	}
	l.Debug("XRP payment tx built successfully")

	txHash, err := c.xrp.Signer.SignAndBroadcast(ctx, *pol, sendTx)
	if err != nil {
		l.WithError(err).Error("failed to sign & broadcast XRP send tx")
		return fmt.Errorf("failed to sign & broadcast XRP send: %w", err)
	}

	l.WithField("txHash", txHash).Info("XRP send tx signed & broadcasted successfully")
	return nil
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

	txHash, err := c.xrp.SwapAssets(ctx, *pol, from, to)
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

func (c *Consumer) handleBtcSend(
	ctx context.Context,
	pol *types.PluginPolicy,
	fromAmount string,
	toAddress string,
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

	from := btc.From{
		PubKey:  childPub,
		Address: fromAddressTyped,
		Amount:  fromAmountSats,
	}

	c.logger.WithFields(logrus.Fields{
		"policyID":    pol.ID.String(),
		"operation":   "send",
		"fromAddress": fromAddressTyped.String(),
		"toAddress":   toAddress,
		"amount":      fromAmountSats,
	}).Info("handling BTC send")

	txHash, err := c.btc.Send(ctx, *pol, from, toAddress, fromAmountSats)
	if err != nil {
		return fmt.Errorf("failed to execute BTC send: %w", err)
	}

	c.logger.WithField("txHash", txHash).Info("BTC send executed successfully")
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

func (c *Consumer) handleSolanaSend(
	ctx context.Context,
	pol *types.PluginPolicy,
	fromAsset string,
	fromAmount string,
	toAddress string,
) error {
	fromAddressTyped, err := c.solanaPubToAddress(pol.PublicKey)
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

	txHash, err := network.Signer.SignAndBroadcast(ctx, fromChain, *pol, swapTx)
	if err != nil {
		return fmt.Errorf("failed to sign & broadcast swap: %w", err)
	}

	l.WithField("txHash", txHash).Info("tx signed & broadcasted")
	return nil
}

func (c *Consumer) handleEvmSend(
	ctx context.Context,
	pol *types.PluginPolicy,
	fromChain common.Chain,
	fromAsset string,
	fromAmount string,
	toAddress string,
) error {
	fromAsset = util.IfEmptyElse(fromAsset, evmsdk.ZeroAddress.String())

	fromAssetTyped := ecommon.HexToAddress(fromAsset)
	fromAddressTyped, err := c.evmPubToAddress(fromChain, pol.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse policy PublicKey: %w", err)
	}

	fromAmountTyped, ok := new(big.Int).SetString(fromAmount, 10)
	if !ok {
		return fmt.Errorf("failed to parse fromAmount %q as integer", fromAmount)
	}

	toAddressTyped := ecommon.HexToAddress(toAddress)

	network, err := c.evm.Get(fromChain)
	if err != nil {
		return fmt.Errorf("failed to get network: %w", err)
	}

	isNative := fromAssetTyped == evmsdk.ZeroAddress

	l := c.logger.WithFields(logrus.Fields{
		"operation":   "send",
		"policyID":    pol.ID.String(),
		"chain":       fromChain.String(),
		"fromAddress": fromAddressTyped.String(),
		"toAddress":   toAddressTyped.String(),
		"asset":       fromAssetTyped.String(),
		"amount":      fromAmountTyped.String(),
		"isNative":    isNative,
	})

	var sendTx []byte
	if isNative {
		l.Info("building native token transfer")
		sendTx, err = network.Send.BuildNativeTransfer(ctx, fromAddressTyped, toAddressTyped, fromAmountTyped)
		if err != nil {
			l.WithError(err).Error("failed to build native transfer")
			return fmt.Errorf("failed to build native transfer: %w", err)
		}
		l.Debug("native transfer tx built successfully")
	} else {
		l.Info("building ERC20 token transfer")
		sendTx, err = network.Send.BuildERC20Transfer(
			ctx,
			fromAssetTyped,
			fromAddressTyped,
			toAddressTyped,
			fromAmountTyped,
		)
		if err != nil {
			l.WithError(err).Error("failed to build ERC20 transfer")
			return fmt.Errorf("failed to build ERC20 transfer: %w", err)
		}
		l.Debug("ERC20 transfer tx built successfully")
	}

	txHash, err := network.Signer.SignAndBroadcast(ctx, fromChain, *pol, sendTx)
	if err != nil {
		l.WithError(err).Error("failed to sign & broadcast send tx")
		return fmt.Errorf("failed to sign & broadcast send: %w", err)
	}

	l.WithField("txHash", txHash).Info("send tx signed & broadcasted successfully")
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
