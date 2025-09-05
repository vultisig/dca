package dca

import (
	"encoding/json"
	"fmt"
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

const (
	endDate = "endDate"
)

// TODO use magic constants
const (
	thorchainBtcRouter = "bc1qd6c3e2kzqy3xkxpjcv4z5h4rq8jk4mh3jvtest"
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
	// Handle EVM same-chain swaps
	if cfg[fromChain] != cfg[toChain] {
		return nil, fmt.Errorf("only same chain swaps supported, got %s->%s", cfg[fromChain], cfg[toChain])
	}

	fromChainStr := cfg[fromChain].(string)
	fromChainLowercase := strings.ToLower(fromChainTyped.String())

	if !fromChainTyped.IsEvm() {
		return nil, fmt.Errorf("chain %s is not an EVM chain", fromChainStr)
	}

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
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
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
				SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
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
				SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
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
	// Get the destination asset for THORChain memo
	toAssetStr := cfg[toAsset].(string)
	toAddressStr := cfg[toAddress].(string)

	// TODO confirm ThorChain memo format
	// Build THORChain memo format: SWAP:ASSET:DESTADDR
	// For native tokens (empty toAsset), use chain's native symbol
	var thorAsset string
	if toAssetStr == "" {
		// Native token - use chain.NativeSymbol
		if nativeSymbol, err := toChain.NativeSymbol(); err == nil {
			thorAsset = toChain.String() + "." + nativeSymbol
		} else {
			// Fallback for chains without native symbol method
			thorAsset = toChain.String() + "." + toChain.String()
		}
	} else {
		// ERC20 token - use format: CHAIN.SYMBOL-ADDRESS
		thorAsset = toChain.String() + ".UNKNOWN-" + toAssetStr
	}

	// Create regex pattern for THORChain memo
	// Format: SWAP:ASSET:DESTADDR
	memoPattern := fmt.Sprintf("^SWAP:%s:%s$",
		strings.ReplaceAll(thorAsset, ".", "\\."),
		strings.ToLower(toAddressStr))

	// Create Bitcoin transaction rule with 3 outputs
	return &rtypes.Rule{
		Resource: "bitcoin.transaction",
		Effect:   rtypes.Effect_EFFECT_ALLOW,
		ParameterConstraints: []*rtypes.ParameterConstraint{
			{
				ParameterName: "output_address_0",
				Constraint: &rtypes.Constraint{
					Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					// TODO swap to magic constant
					Value: &rtypes.Constraint_FixedValue{
						FixedValue: thorchainBtcRouter,
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
					Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Value: &rtypes.Constraint_FixedValue{
						FixedValue: memoPattern,
					},
				},
			},
		},
		Target: &rtypes.Target{
			TargetType: rtypes.TargetType_TARGET_TYPE_ADDRESS,
			Target: &rtypes.Target_Address{
				Address: thorchainBtcRouter,
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
	return &rtypes.Rule{
		Resource: chainName + ".erc20.approve",
		Effect:   rtypes.Effect_EFFECT_ALLOW,
		ParameterConstraints: []*rtypes.ParameterConstraint{{
			ParameterName: "spender",
			Constraint: &rtypes.Constraint{
				Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
				Value: &rtypes.Constraint_FixedValue{
					FixedValue: spenderAddress,
				},
			},
		}, {
			ParameterName: "amount",
			Constraint: &rtypes.Constraint{
				Type: rtypes.ConstraintType_CONSTRAINT_TYPE_ANY,
			},
		}},
		Target: &rtypes.Target{
			TargetType: rtypes.TargetType_TARGET_TYPE_ADDRESS,
			Target: &rtypes.Target_Address{
				Address: tokenAddress,
			},
		},
	}
}
