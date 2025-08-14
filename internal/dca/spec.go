package dca

import (
	"encoding/json"
	"fmt"
	"strings"

	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/kaptinlin/jsonschema"
	"github.com/vultisig/recipes/common"
	"github.com/vultisig/recipes/sdk/evm"
	rtypes "github.com/vultisig/recipes/types"
	"github.com/vultisig/verifier/plugin"
	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/conv"
	"github.com/vultisig/verifier/types"
)

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

	if err := schema.Validate(cfg); err != nil {
		return fmt.Errorf("configuration validation error: %w", err)
	}

	return nil
}

func (s *Spec) Suggest(cfg map[string]any) (*rtypes.PolicySuggest, error) {
	if err := s.validateConfiguration(cfg); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	if cfg[fromChain] != cfg[toChain] {
		return nil, fmt.Errorf("only same chain swaps supported, got %s->%s", cfg[fromChain], cfg[toChain])
	}

	ethRouterV2, ok := s.uniswapRouterV2[common.Ethereum]
	if !ok {
		return nil, fmt.Errorf("ethereum router v2 address not found")
	}

	fromAssetAddr := ecommon.HexToAddress(cfg[fromAsset].(string))
	toAssetAddr := ecommon.HexToAddress(cfg[toAsset].(string))
	isFromNative := fromAssetAddr == evm.ZeroAddress
	isToNative := toAssetAddr == evm.ZeroAddress

	var rules []*rtypes.Rule
	if isFromNative {
		rules = append(rules, createUniswapRule(
			"ethereum.uniswapV2_router.swapExactETHForTokens",
			cfg,
			ethRouterV2.Hex(),
			false,
		))
	} else if isToNative {
		rules = append(rules, createUniswapRule(
			"ethereum.uniswapV2_router.swapExactTokensForETH",
			cfg,
			ethRouterV2.Hex(),
			true,
		), createApproveRule(ethRouterV2.Hex(), cfg[fromAsset].(string)))
	} else {
		rules = append(rules, createUniswapRule(
			"ethereum.uniswapV2_router.swapExactTokensForTokens",
			cfg,
			ethRouterV2.Hex(),
			true,
		), createApproveRule(ethRouterV2.Hex(), cfg[fromAsset].(string)))
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

func (s *Spec) GetRecipeSpecification() (*rtypes.RecipeSchema, error) {
	cfg, err := plugin.RecipeConfiguration(map[string]any{
		"type": "object",
		"properties": map[string]any{
			fromChain: map[string]any{
				"type": "string",
				"enum": []any{
					common.Ethereum.String(),
				},
			},
			fromAsset: map[string]any{
				"type": "string",
			},
			fromAmount: map[string]any{
				"type": "number",
			},
			toChain: map[string]any{
				"type": "string",
				"enum": []any{
					common.Ethereum.String(),
				},
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
			fromAsset,
			fromAmount,
			toChain,
			toAsset,
			toAddress,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build pb recipe config: %w", err)
	}

	return &rtypes.RecipeSchema{
		Version:       1, // Schema version
		PluginId:      string(types.PluginVultisigDCA_0000),
		PluginName:    "DCA",
		PluginVersion: 1,
		SupportedResources: []*rtypes.ResourcePattern{
			{
				ResourcePath: &rtypes.ResourcePath{
					ChainId:    "ethereum",
					ProtocolId: "uniswapV2_router",
					FunctionId: "swapExactTokensForTokens",
					Full:       "ethereum.uniswapV2_router.swapExactTokensForTokens",
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
			},
			{
				ResourcePath: &rtypes.ResourcePath{
					ChainId:    "ethereum",
					ProtocolId: "uniswapV2_router",
					FunctionId: "swapExactETHForTokens",
					Full:       "ethereum.uniswapV2_router.swapExactETHForTokens",
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
			},
			{
				ResourcePath: &rtypes.ResourcePath{
					ChainId:    "ethereum",
					ProtocolId: "uniswapV2_router",
					FunctionId: "swapExactTokensForETH",
					Full:       "ethereum.uniswapV2_router.swapExactTokensForETH",
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
			},
			{
				ResourcePath: &rtypes.ResourcePath{
					ChainId:    "ethereum",
					ProtocolId: "erc20",
					FunctionId: "approve",
					Full:       "ethereum.erc20.approve",
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
			},
		},
		Configuration: cfg,
		Requirements: &rtypes.PluginRequirements{
			MinVultisigVersion: 1,
			SupportedChains: []string{
				common.Ethereum.String(),
			},
		},
	}, nil
}

func (s *Spec) ValidatePluginPolicy(pol types.PluginPolicy) error {
	spec, err := s.GetRecipeSpecification()
	if err != nil {
		return fmt.Errorf("failed to get recipe spec: %w", err)
	}
	return plugin.ValidatePluginPolicy(pol, spec)
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

func createApproveRule(spenderAddress, tokenAddress string) *rtypes.Rule {
	return &rtypes.Rule{
		Resource: "ethereum.erc20.approve",
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
