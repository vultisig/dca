package dca

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/kaptinlin/jsonschema"
	"github.com/vultisig/recipes/sdk/evm"
	rtypes "github.com/vultisig/recipes/types"
	"github.com/vultisig/verifier/plugin"
	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/conv"
	"github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/common"
)

var supportedChains = []common.Chain{
	common.Ethereum,
	common.Arbitrum,
	common.Avalanche,
	common.BscChain,
	common.Base,
	common.Blast,
	common.Optimism,
	common.Polygon,
	common.Bitcoin,
}

const (
	fromChain  = "fromChain"
	fromAsset  = "fromAsset"
	fromAmount = "fromAmount"

	toChain   = "toChain"
	toAsset   = "toAsset"
	toAddress = "toAddress"
)

// THORChain memo pattern templates
const (
	// Pattern for native BTC only: SWAP:BTC.BTC:address or =:b:address
	memoPatternNativeBTC = "^(SWAP|=):(BTC\\.BTC|b):%s(:.*)?$"
	
	// Pattern for native token on specific EVM chain: SWAP:ETH.ETH:address or =:e:address
	memoPatternNativeEVM = "^(SWAP|=):(%s\\.%s|[a-z]):%s(:.*)?$"
	
	// Pattern for any token on specific EVM chain: SWAP:ETH.USDC-0x123:address or =:e:address
	memoPatternEvmToken = "^(SWAP|=):(%s\\.[A-Z0-9.-]+|[a-z]):%s(:.*)?$"
	
	// Pattern for any asset to specific address: SWAP:ANYTHING:address
	memoPatternAnyAsset = "^(SWAP|=):[a-zA-Z0-9.-]+:%s(:.*)?$"
)

const (
	endDate = "endDate"
)

const (
	frequency = "frequency"

	minutely = "minutely"
	hourly   = "hourly"
	daily    = "daily"
	weekly   = "weekly"
	biWeekly = "bi-weekly"
	monthly  = "monthly"
)

type Spec struct {
	plugin.Unimplemented
	uniswapRouterV2 map[common.Chain]ecommon.Address
}

func NewSpec(uniswapRouterV2 map[common.Chain]ecommon.Address) *Spec {
	return &Spec{
		uniswapRouterV2: uniswapRouterV2,
	}
}

func (s *Spec) validateConfiguration(cfg map[string]any) error {
	spec, err := s.GetRecipeSpecification()
	if err != nil {
		return fmt.Errorf("failed to get recipe specification: %w", err)
	}

	schemaMap := spec.Configuration.AsMap()
	schemaBytes, err := json.Marshal(schemaMap)
	if err != nil {
		return fmt.Errorf("failed to marshal schema: %w", err)
	}

	compiler := jsonschema.NewCompiler()
	schema, err := compiler.Compile(schemaBytes)
	if err != nil {
		return fmt.Errorf("failed to compile JSON schema: %w", err)
	}

	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	res := schema.Validate(cfgBytes)
	if !res.IsValid() {
		var errStrs []string
		for _, e := range res.Errors {
			errStrs = append(errStrs, e.Error())
		}
		return fmt.Errorf("configuration validation error: %s", strings.Join(errStrs, ", "))
	}

	return nil
}

func (s *Spec) Suggest(cfg map[string]any) (*rtypes.PolicySuggest, error) {
	if err := s.validateConfiguration(cfg); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	fromChainStr := cfg[fromChain].(string)
	fromChainTyped, err := common.FromString(fromChainStr)
	if err != nil {
		return nil, fmt.Errorf("unsupported chain: %s", fromChainStr)
	}

	var rules []*rtypes.Rule

	// Handle Bitcoin
	if fromChainTyped == common.Bitcoin {
		rules, err = s.suggestBitcoinRule(cfg, fromChainTyped)
	} else {
		// Handle EVM same-chain swaps
		rules, err = s.suggestEvmRule(cfg, fromChainTyped)
	}

	if err != nil {
		return nil, err
	}

	var rateLimitWindow uint32
	freq := cfg[frequency].(string)

	switch freq {
	case minutely:
		rateLimitWindow = 60
	case hourly:
		rateLimitWindow = 3600
	case daily:
		rateLimitWindow = 86400
	case weekly:
		rateLimitWindow = 604800
	case biWeekly:
		rateLimitWindow = 1209600
	case monthly:
		rateLimitWindow = 2592000
	default:
		return nil, fmt.Errorf("unknown frequency: %s", freq)
	}

	return &rtypes.PolicySuggest{
		RateLimitWindow: conv.Ptr(rateLimitWindow),
		MaxTxsPerWindow: conv.Ptr(uint32(len(rules))),
		Rules:           rules,
	}, nil
}

func (s *Spec) suggestBitcoinRule(cfg map[string]any, fromChain common.Chain) ([]*rtypes.Rule, error) {
	// Parse to chain for THORChain memo
	toChainStr := cfg[toChain].(string)
	toChainTyped, err := common.FromString(toChainStr)
	if err != nil {
		return nil, fmt.Errorf("unsupported to chain: %s", toChainStr)
	}

	// Create Bitcoin transaction rule with 3 outputs
	rules := []*rtypes.Rule{
		s.createBitcoinThorchainRule(cfg, fromChain, toChainTyped),
	}

	return rules, nil
}

func (s *Spec) suggestEvmRule(cfg map[string]any, fromChainTyped common.Chain) ([]*rtypes.Rule, error) {
	fromChainStr := cfg[fromChain].(string)
	toChainStr := cfg[toChain].(string)

	if !fromChainTyped.IsEvm() {
		return nil, fmt.Errorf("chain %s is not an EVM chain", fromChainStr)
	}

	// Parse to chain
	toChainTyped, err := common.FromString(toChainStr)
	if err != nil {
		return nil, fmt.Errorf("unsupported to chain: %s", toChainStr)
	}

	// Branch based on same-chain vs cross-chain
	if fromChainStr == toChainStr {
		// Same chain: Use Uniswap V2
		return s.suggestEvmUniswapRule(cfg, fromChainTyped)
	} else {
		// Cross chain: Use THORChain router
		return s.suggestEvmThorchainRule(cfg, fromChainTyped, toChainTyped)
	}
}

func (s *Spec) suggestEvmUniswapRule(cfg map[string]any, fromChainTyped common.Chain) ([]*rtypes.Rule, error) {
	fromChainStr := cfg[fromChain].(string)
	fromChainLowercase := strings.ToLower(fromChainTyped.String())

	routerV2, ok := s.uniswapRouterV2[fromChainTyped]
	if !ok {
		return nil, fmt.Errorf("%s router v2 address not found", fromChainStr)
	}

	fromAssetAddr := ecommon.HexToAddress(cfg[fromAsset].(string))
	toAssetAddr := ecommon.HexToAddress(cfg[toAsset].(string))
	isFromNative := fromAssetAddr == evm.ZeroAddress
	isToNative := toAssetAddr == evm.ZeroAddress

	var rules []*rtypes.Rule
	if isFromNative {
		rules = append(rules, createUniswapRule(
			fromChainLowercase+".uniswapV2_router.swapExactETHForTokens",
			cfg,
			routerV2.Hex(),
			false,
		))
	} else if isToNative {
		rules = append(rules, createUniswapRule(
			fromChainLowercase+".uniswapV2_router.swapExactTokensForETH",
			cfg,
			routerV2.Hex(),
			true,
		), createApproveRule(routerV2.Hex(), cfg[fromAsset].(string), fromChainLowercase))
	} else {
		rules = append(rules, createUniswapRule(
			fromChainLowercase+".uniswapV2_router.swapExactTokensForTokens",
			cfg,
			routerV2.Hex(),
			true,
		), createApproveRule(routerV2.Hex(), cfg[fromAsset].(string), fromChainLowercase))
	}

	return rules, nil
}

func (s *Spec) suggestEvmThorchainRule(cfg map[string]any, fromChain, toChain common.Chain) ([]*rtypes.Rule, error) {
	fromChainLowercase := strings.ToLower(fromChain.String())

	// Get assets from config
	fromAssetStr := cfg[fromAsset].(string)
	fromAssetAddr := ecommon.HexToAddress(fromAssetStr)
	isFromNative := fromAssetAddr == evm.ZeroAddress

	var rules []*rtypes.Rule

	if isFromNative {
		// Native token (ETH) -> THORChain
		rules = append(rules, s.createEvmThorchainDepositRule(
			fromChainLowercase+".thorchain_router.depositWithExpiry",
			cfg,
			true,
		))
	} else {
		// ERC20 token -> THORChain
		rules = append(rules,
			// Need approval for ERC20 token first
			createApproveRule("", cfg[fromAsset].(string), fromChainLowercase), // empty spender = THORChain vault
			// Then depositWithExpiry
			s.createEvmThorchainDepositRule(
				fromChainLowercase+".thorchain_router.depositWithExpiry",
				cfg,
				false,
			),
		)
	}

	return rules, nil
}

func (s *Spec) GetRecipeSpecification() (*rtypes.RecipeSchema, error) {
	var chains []any
	for _, chain := range supportedChains {
		chains = append(chains, chain.String())
	}

	cfg, err := plugin.RecipeConfiguration(map[string]any{
		"type": "object",
		"properties": map[string]any{
			fromChain: map[string]any{
				"type": "string",
				"enum": chains,
			},
			fromAsset: map[string]any{
				"type": "string",
			},
			fromAmount: map[string]any{
				"type": "string",
			},
			toChain: map[string]any{
				"type": "string",
				"enum": chains,
			},
			toAsset: map[string]any{
				"type": "string",
			},
			toAddress: map[string]any{
				"type": "string",
			},
			endDate: map[string]any{
				"type":   "string",
				"format": "date-time",
			},
			frequency: map[string]any{
				"type": "string",
				"enum": []any{
					minutely,
					hourly,
					daily,
					weekly,
					biWeekly,
					monthly,
				},
			},
		},
		"required": []any{
			frequency,
			fromChain,
			fromAmount,
			toChain,
			toAddress,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build pb recipe config: %w", err)
	}

	return &rtypes.RecipeSchema{
		Version:            1,
		PluginId:           string(types.PluginVultisigDCA_0000),
		PluginName:         "DCA",
		PluginVersion:      1,
		SupportedResources: s.buildSupportedResources(),
		Configuration:      cfg,
		Requirements: &rtypes.PluginRequirements{
			MinVultisigVersion: 1,
			SupportedChains: func() []string {
				var cc []string
				for _, c := range supportedChains {
					cc = append(cc, c.String())
				}
				return cc
			}(),
		},
	}, nil
}

func (s *Spec) buildSupportedResources() []*rtypes.ResourcePattern {
	var resources []*rtypes.ResourcePattern
	for _, chain := range supportedChains {
		chainNameLower := strings.ToLower(chain.String())

		resources = append(resources, &rtypes.ResourcePattern{
			ResourcePath: &rtypes.ResourcePath{
				ChainId:    chainNameLower,
				ProtocolId: "uniswapV2_router",
				FunctionId: "swapExactTokensForTokens",
				Full:       chainNameLower + ".uniswapV2_router.swapExactTokensForTokens",
			},
			Target: rtypes.TargetType_TARGET_TYPE_ADDRESS,
			ParameterCapabilities: []*rtypes.ParameterConstraintCapability{
				{
					ParameterName:  "amountIn",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Required:       true,
				},
				{
					ParameterName:  "amountOutMin",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_ANY,
					Required:       true,
				},
				{
					ParameterName:  "path",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Required:       true,
				},
				{
					ParameterName:  "to",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Required:       true,
				},
				{
					ParameterName:  "deadline",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_ANY,
					Required:       true,
				},
			},
			Required: true,
		})

		resources = append(resources, &rtypes.ResourcePattern{
			ResourcePath: &rtypes.ResourcePath{
				ChainId:    chainNameLower,
				ProtocolId: "uniswapV2_router",
				FunctionId: "swapExactETHForTokens",
				Full:       chainNameLower + ".uniswapV2_router.swapExactETHForTokens",
			},
			Target: rtypes.TargetType_TARGET_TYPE_ADDRESS,
			ParameterCapabilities: []*rtypes.ParameterConstraintCapability{
				{
					ParameterName:  "amountOutMin",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_ANY,
					Required:       true,
				},
				{
					ParameterName:  "path",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Required:       true,
				},
				{
					ParameterName:  "to",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Required:       true,
				},
				{
					ParameterName:  "deadline",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_ANY,
					Required:       true,
				},
			},
			Required: true,
		})

		resources = append(resources, &rtypes.ResourcePattern{
			ResourcePath: &rtypes.ResourcePath{
				ChainId:    chainNameLower,
				ProtocolId: "uniswapV2_router",
				FunctionId: "swapExactTokensForETH",
				Full:       chainNameLower + ".uniswapV2_router.swapExactTokensForETH",
			},
			Target: rtypes.TargetType_TARGET_TYPE_ADDRESS,
			ParameterCapabilities: []*rtypes.ParameterConstraintCapability{
				{
					ParameterName:  "amountIn",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Required:       true,
				},
				{
					ParameterName:  "amountOutMin",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_ANY,
					Required:       true,
				},
				{
					ParameterName:  "path",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Required:       true,
				},
				{
					ParameterName:  "to",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Required:       true,
				},
				{
					ParameterName:  "deadline",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_ANY,
					Required:       true,
				},
			},
			Required: true,
		})

		resources = append(resources, &rtypes.ResourcePattern{
			ResourcePath: &rtypes.ResourcePath{
				ChainId:    chainNameLower,
				ProtocolId: "erc20",
				FunctionId: "approve",
				Full:       chainNameLower + ".erc20.approve",
			},
			Target: rtypes.TargetType_TARGET_TYPE_ADDRESS,
			ParameterCapabilities: []*rtypes.ParameterConstraintCapability{
				{
					ParameterName:  "spender",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED | rtypes.ConstraintType_CONSTRAINT_TYPE_MAGIC_CONSTANT,
					Required:       true,
				},
				{
					ParameterName:  "amount",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_ANY,
					Required:       true,
				},
			},
			Required: true,
		})

		// Add THORChain router support for cross-chain swaps
		resources = append(resources, &rtypes.ResourcePattern{
			ResourcePath: &rtypes.ResourcePath{
				ChainId:    chainNameLower,
				ProtocolId: "thorchain_router",
				FunctionId: "depositWithExpiry",
				Full:       chainNameLower + ".thorchain_router.depositWithExpiry",
			},
			Target: rtypes.TargetType_TARGET_TYPE_MAGIC_CONSTANT,
			ParameterCapabilities: []*rtypes.ParameterConstraintCapability{
				{
					ParameterName:  "vault",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_MAGIC_CONSTANT,
					Required:       true,
				},
				{
					ParameterName:  "asset",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Required:       true,
				},
				{
					ParameterName:  "amount",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Required:       true,
				},
				{
					ParameterName:  "memo",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_REGEXP,
					Required:       true,
				},
				{
					ParameterName:  "expiry",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_ANY,
					Required:       true,
				},
			},
			Required: true,
		})
	}

	// Add Bitcoin transaction support for THORChain bridging
	resources = append(resources, &rtypes.ResourcePattern{
		ResourcePath: &rtypes.ResourcePath{
			ChainId:    "bitcoin",
			ProtocolId: "transaction",
			FunctionId: "",
			Full:       "bitcoin.transaction",
		},
		Target: rtypes.TargetType_TARGET_TYPE_ADDRESS,
		ParameterCapabilities: []*rtypes.ParameterConstraintCapability{
			{
				ParameterName:  "output_address_0",
				SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_MAGIC_CONSTANT,
				Required:       true,
			},
			{
				ParameterName:  "output_value_0",
				SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
				Required:       true,
			},
			{
				ParameterName:  "output_address_1",
				SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
				Required:       true,
			},
			{
				ParameterName:  "output_value_1",
				SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_ANY,
				Required:       true,
			},
			{
				ParameterName:  "output_data_2",
				SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_REGEXP,
				Required:       true,
			},
		},
		Required: true,
	})

	return resources
}

func (s *Spec) ValidatePluginPolicy(pol types.PluginPolicy) error {
	spec, err := s.GetRecipeSpecification()
	if err != nil {
		return fmt.Errorf("failed to get recipe spec: %w", err)
	}
	return plugin.ValidatePluginPolicy(pol, spec)
}

func (s *Spec) createBitcoinThorchainRule(cfg map[string]any, fromChain, toChain common.Chain) *rtypes.Rule {
	toAddressStr := cfg[toAddress].(string)

	var memoPattern string

	if fromChain.String() == toChain.String() {
		// BTC->BTC: Enforce native BTC only
		memoPattern = fmt.Sprintf(memoPatternNativeBTC, regexp.QuoteMeta(toAddressStr))
	} else {
		// BTC->Other chain: Allow any asset on target chain to specific address
		memoPattern = fmt.Sprintf(memoPatternAnyAsset, regexp.QuoteMeta(toAddressStr))
	}

	// Create Bitcoin transaction rule with 3 outputs
	return &rtypes.Rule{
		Resource: "bitcoin.transaction",
		Effect:   rtypes.Effect_EFFECT_ALLOW,
		ParameterConstraints: []*rtypes.ParameterConstraint{
			{
				ParameterName: "output_address_0",
				Constraint: &rtypes.Constraint{
					Type: rtypes.ConstraintType_CONSTRAINT_TYPE_MAGIC_CONSTANT,
					Value: &rtypes.Constraint_MagicConstantValue{
						MagicConstantValue: rtypes.MagicConstant_THORCHAIN_VAULT,
					},
				},
			},
			{
				ParameterName: "output_value_0",
				Constraint: &rtypes.Constraint{
					Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Value: &rtypes.Constraint_FixedValue{
						FixedValue: cfg[fromAmount].(string),
					},
				},
			},
			{
				ParameterName: "output_address_1",
				Constraint: &rtypes.Constraint{
					Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Value: &rtypes.Constraint_FixedValue{
						FixedValue: toAddressStr,
					},
				},
			},
			{
				ParameterName: "output_value_1",
				Constraint: &rtypes.Constraint{
					Type: rtypes.ConstraintType_CONSTRAINT_TYPE_ANY,
				},
			},
			{
				ParameterName: "output_data_2",
				Constraint: &rtypes.Constraint{
					Type: rtypes.ConstraintType_CONSTRAINT_TYPE_REGEXP,
					Value: &rtypes.Constraint_RegexpValue{
						RegexpValue: memoPattern,
					},
				},
			},
		},
		Target: &rtypes.Target{
			TargetType: rtypes.TargetType_TARGET_TYPE_MAGIC_CONSTANT,
			Target: &rtypes.Target_MagicConstant{
				MagicConstant: rtypes.MagicConstant_THORCHAIN_VAULT,
			},
		},
	}
}

func createUniswapRule(resource string, cfg map[string]any, routerAddress string, includeAmountIn bool) *rtypes.Rule {
	var constraints []*rtypes.ParameterConstraint

	if includeAmountIn {
		constraints = append(constraints, &rtypes.ParameterConstraint{
			ParameterName: "amountIn",
			Constraint: &rtypes.Constraint{
				Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
				Value: &rtypes.Constraint_FixedValue{
					FixedValue: cfg[fromAmount].(string),
				},
			},
		})
	}

	constraints = append(constraints, &rtypes.ParameterConstraint{
		ParameterName: "amountOutMin",
		Constraint: &rtypes.Constraint{
			Type: rtypes.ConstraintType_CONSTRAINT_TYPE_ANY,
		},
	}, &rtypes.ParameterConstraint{
		ParameterName: "path",
		Constraint: &rtypes.Constraint{
			Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
			Value: &rtypes.Constraint_FixedValue{
				FixedValue: strings.Join([]string{
					cfg[fromAsset].(string),
					cfg[toAsset].(string),
				}, ","),
			},
		},
	}, &rtypes.ParameterConstraint{
		ParameterName: "to",
		Constraint: &rtypes.Constraint{
			Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
			Value: &rtypes.Constraint_FixedValue{
				FixedValue: cfg[toAddress].(string),
			},
		},
	}, &rtypes.ParameterConstraint{
		ParameterName: "deadline",
		Constraint: &rtypes.Constraint{
			Type: rtypes.ConstraintType_CONSTRAINT_TYPE_ANY,
		},
	})

	return &rtypes.Rule{
		Resource:             resource,
		Effect:               rtypes.Effect_EFFECT_ALLOW,
		ParameterConstraints: constraints,
		Target: &rtypes.Target{
			TargetType: rtypes.TargetType_TARGET_TYPE_ADDRESS,
			Target: &rtypes.Target_Address{
				Address: routerAddress,
			},
		},
	}
}

func createApproveRule(spenderAddress, tokenAddress, chainName string) *rtypes.Rule {
	var spenderConstraint *rtypes.Constraint

	// Check if spenderAddress is a magic constant indicator (empty string means use THORChain vault)
	if spenderAddress == "" {
		spenderConstraint = &rtypes.Constraint{
			Type: rtypes.ConstraintType_CONSTRAINT_TYPE_MAGIC_CONSTANT,
			Value: &rtypes.Constraint_MagicConstantValue{
				MagicConstantValue: rtypes.MagicConstant_THORCHAIN_VAULT,
			},
		}
	} else {
		spenderConstraint = &rtypes.Constraint{
			Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
			Value: &rtypes.Constraint_FixedValue{
				FixedValue: spenderAddress,
			},
		}
	}

	return &rtypes.Rule{
		Resource: chainName + ".erc20.approve",
		Effect:   rtypes.Effect_EFFECT_ALLOW,
		ParameterConstraints: []*rtypes.ParameterConstraint{
			{
				ParameterName: "spender",
				Constraint:    spenderConstraint,
			},
			{
				ParameterName: "amount",
				Constraint: &rtypes.Constraint{
					Type: rtypes.ConstraintType_CONSTRAINT_TYPE_ANY,
				},
			},
		},
		Target: &rtypes.Target{
			TargetType: rtypes.TargetType_TARGET_TYPE_ADDRESS,
			Target: &rtypes.Target_Address{
				Address: tokenAddress,
			},
		},
	}
}

func (s *Spec) createEvmThorchainDepositRule(resource string, cfg map[string]any, isNative bool) *rtypes.Rule {
	var constraints []*rtypes.ParameterConstraint

	// vault parameter - use magic constant for THORChain vault
	constraints = append(constraints, &rtypes.ParameterConstraint{
		ParameterName: "vault",
		Constraint: &rtypes.Constraint{
			Type: rtypes.ConstraintType_CONSTRAINT_TYPE_MAGIC_CONSTANT,
			Value: &rtypes.Constraint_MagicConstantValue{
				MagicConstantValue: rtypes.MagicConstant_THORCHAIN_VAULT,
			},
		},
	})

	// asset parameter - token address (zero address for native)
	constraints = append(constraints, &rtypes.ParameterConstraint{
		ParameterName: "asset",
		Constraint: &rtypes.Constraint{
			Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
			Value: &rtypes.Constraint_FixedValue{
				FixedValue: cfg[fromAsset].(string),
			},
		},
	})

	// amount parameter
	if isNative {
		// For native tokens, amount is sent as value, so amount parameter is 0
		constraints = append(constraints, &rtypes.ParameterConstraint{
			ParameterName: "amount",
			Constraint: &rtypes.Constraint{
				Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
				Value: &rtypes.Constraint_FixedValue{
					FixedValue: "0",
				},
			},
		})
	} else {
		// For ERC20 tokens, amount parameter is the token amount
		constraints = append(constraints, &rtypes.ParameterConstraint{
			ParameterName: "amount",
			Constraint: &rtypes.Constraint{
				Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
				Value: &rtypes.Constraint_FixedValue{
					FixedValue: cfg[fromAmount].(string),
				},
			},
		})
	}

	// memo parameter - THORChain swap memo format
	toAssetStr := cfg[toAsset].(string)
	toAddressStr := cfg[toAddress].(string)
	toChainStr := cfg[toChain].(string)
	fromChainStr := cfg[fromChain].(string)

	// Parse to chain for type checking
	toChainTyped, _ := common.FromString(toChainStr)

	var memoPattern string

	if toChainTyped.IsEvm() {
		// EVM destination
		if fromChainStr == toChainStr {
			// Same EVM chain: Check native vs non-native
			if toAssetStr == "" {
				// Native token (ETH.ETH, AVAX.AVAX, etc.)
				chainUpper := strings.ToUpper(toChainStr)
				memoPattern = fmt.Sprintf(memoPatternNativeEVM,
					chainUpper, chainUpper, regexp.QuoteMeta(toAddressStr))
			} else {
				// ERC20 token - allow any token on same chain
				chainUpper := strings.ToUpper(toChainStr)
				memoPattern = fmt.Sprintf(memoPatternEvmToken,
					chainUpper, regexp.QuoteMeta(toAddressStr))
			}
		} else {
			// Different EVM chain: Allow any asset on target chain
			memoPattern = fmt.Sprintf(memoPatternAnyAsset, regexp.QuoteMeta(toAddressStr))
		}
	} else {
		// Non-EVM destination (Bitcoin): Enforce native only
		memoPattern = fmt.Sprintf(memoPatternNativeBTC, regexp.QuoteMeta(toAddressStr))
	}

	constraints = append(constraints, &rtypes.ParameterConstraint{
		ParameterName: "memo",
		Constraint: &rtypes.Constraint{
			Type: rtypes.ConstraintType_CONSTRAINT_TYPE_REGEXP,
			Value: &rtypes.Constraint_RegexpValue{
				RegexpValue: memoPattern,
			},
		},
	})

	// expiry parameter - allow dynamic expiry
	constraints = append(constraints, &rtypes.ParameterConstraint{
		ParameterName: "expiry",
		Constraint: &rtypes.Constraint{
			Type: rtypes.ConstraintType_CONSTRAINT_TYPE_ANY,
		},
	})

	return &rtypes.Rule{
		Resource:             resource,
		Effect:               rtypes.Effect_EFFECT_ALLOW,
		ParameterConstraints: constraints,
		Target: &rtypes.Target{
			TargetType: rtypes.TargetType_TARGET_TYPE_MAGIC_CONSTANT,
			Target: &rtypes.Target_MagicConstant{
				MagicConstant: rtypes.MagicConstant_THORCHAIN_VAULT,
			},
		},
	}
}
