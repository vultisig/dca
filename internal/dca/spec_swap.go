package dca

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kaptinlin/jsonschema"
	"github.com/vultisig/dca/internal/util"
	rjsonschema "github.com/vultisig/recipes/jsonschema"
	rtypes "github.com/vultisig/recipes/types"
	"github.com/vultisig/verifier/plugin"
	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/conv"
	"github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/common"
	"google.golang.org/protobuf/types/known/structpb"
)

type SwapSpec struct {
	plugin.Unimplemented
}

func NewSwapSpec() *SwapSpec {
	return &SwapSpec{}
}

func (s *SwapSpec) validateConfiguration(cfg map[string]any) error {
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

func (s *SwapSpec) Suggest(cfg map[string]any) (*rtypes.PolicySuggest, error) {
	err := s.validateConfiguration(cfg)
	if err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	fromAssetMap, ok := cfg[fromAsset].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("'from' must be an object")
	}

	fromChainStr, ok := fromAssetMap["chain"].(string)
	if !ok {
		return nil, fmt.Errorf("'from.chain' could not be empty")
	}

	fromChainTyped, err := common.FromString(fromChainStr)
	if err != nil {
		return nil, fmt.Errorf("unsupported chain: %s", fromChainStr)
	}

	rule, err := s.createSwapMetaRule(cfg, fromChainTyped)
	if err != nil {
		return nil, fmt.Errorf("failed to create swap meta rule: %w", err)
	}

	freq := cfg[frequency].(string)
	rateLimitWindow, err := getRateLimitWindow(freq)
	if err != nil {
		return nil, err
	}

	maxTxsPerWindow := getMaxTxsForSwap(fromChainTyped)

	return &rtypes.PolicySuggest{
		RateLimitWindow: conv.Ptr(rateLimitWindow),
		MaxTxsPerWindow: conv.Ptr(maxTxsPerWindow),
		Rules:           []*rtypes.Rule{rule},
	}, nil
}

func (s *SwapSpec) createSwapMetaRule(cfg map[string]any, fromChainTyped common.Chain) (*rtypes.Rule, error) {
	fromChainLowercase := strings.ToLower(fromChainTyped.String())

	fromAssetMap, ok := cfg[fromAsset].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("'from' must be an object")
	}

	toAssetMap, ok := cfg[toAsset].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("'to' must be an object")
	}

	fromAddressStr, ok := fromAssetMap["address"].(string)
	if !ok || fromAddressStr == "" {
		return nil, fmt.Errorf("'from.address' could not be empty")
	}

	toAddressStr, ok := toAssetMap["address"].(string)
	if !ok || toAddressStr == "" {
		return nil, fmt.Errorf("'to.address' could not be empty")
	}

	toChainStr, ok := toAssetMap["chain"].(string)
	if !ok || toChainStr == "" {
		return nil, fmt.Errorf("'to.chain' could not be empty")
	}

	fromAmountStr := util.GetStr(cfg, fromAmount)
	if fromAmountStr == "" {
		return nil, fmt.Errorf("'fromAmount' could not be empty")
	}

	fromAssetTokenStr := util.GetStr(fromAssetMap, "token")
	toAssetTokenStr := util.GetStr(toAssetMap, "token")

	return &rtypes.Rule{
		Resource: fromChainLowercase + ".swap",
		Effect:   rtypes.Effect_EFFECT_ALLOW,
		ParameterConstraints: []*rtypes.ParameterConstraint{
			{
				ParameterName: "from_asset",
				Constraint: &rtypes.Constraint{
					Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Value: &rtypes.Constraint_FixedValue{
						FixedValue: fromAssetTokenStr,
					},
					Required: false,
				},
			},
			{
				ParameterName: "from_address",
				Constraint: &rtypes.Constraint{
					Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Value: &rtypes.Constraint_FixedValue{
						FixedValue: fromAddressStr,
					},
					Required: true,
				},
			},
			{
				ParameterName: "from_amount",
				Constraint: &rtypes.Constraint{
					Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Value: &rtypes.Constraint_FixedValue{
						FixedValue: fromAmountStr,
					},
					Required: true,
				},
			},
			{
				ParameterName: "to_chain",
				Constraint: &rtypes.Constraint{
					Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Value: &rtypes.Constraint_FixedValue{
						FixedValue: strings.ToLower(toChainStr),
					},
					Required: true,
				},
			},
			{
				ParameterName: "to_asset",
				Constraint: &rtypes.Constraint{
					Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Value: &rtypes.Constraint_FixedValue{
						FixedValue: toAssetTokenStr,
					},
					Required: false,
				},
			},
			{
				ParameterName: "to_address",
				Constraint: &rtypes.Constraint{
					Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Value: &rtypes.Constraint_FixedValue{
						FixedValue: toAddressStr,
					},
					Required: true,
				},
			},
		},
		Target: &rtypes.Target{
			TargetType: rtypes.TargetType_TARGET_TYPE_UNSPECIFIED,
		},
	}, nil
}

func (s *SwapSpec) GetRecipeSpecification() (*rtypes.RecipeSchema, error) {
	asset := rjsonschema.NewAsset()

	cfg, err := plugin.RecipeConfiguration(map[string]any{
		"type":        "object",
		"definitions": rjsonschema.Definitions(),
		"properties": map[string]any{
			fromAsset: map[string]any{
				"$ref": "#/definitions/" + asset.Name(),
			},
			toAsset: map[string]any{
				"$ref": "#/definitions/" + asset.Name(),
			},
			fromAmount: map[string]any{
				"type": "string",
			},
			endDate: map[string]any{
				"type":   "string",
				"format": "date-time",
			},
			frequency: map[string]any{
				"type": "string",
				"enum": []any{
					onetime,
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
			fromAsset,
			toAsset,
			fromAmount,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build pb recipe config: %w", err)
	}

	cfgExample1, err := plugin.RecipeConfiguration(map[string]any{
		fromAsset: map[string]any{
			"chain":   "Ethereum",
			"token":   "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
			"address": "",
		},
		toAsset: map[string]any{
			"chain":   "Ethereum",
			"token":   "0xdac17f958d2ee523a2206206994597c13d831ec7",
			"address": "",
		},
		fromAmount: "10000000",
		endDate:    "2026-12-25T00:00:00Z",
		frequency:  daily,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build pb recipe config example1: %w", err)
	}

	cfgExamples := []*structpb.Struct{cfgExample1}

	return &rtypes.RecipeSchema{
		Version:              1,
		PluginId:             PluginRecurringSwaps,
		PluginName:           "Recurring Swaps",
		PluginVersion:        1,
		SupportedResources:   s.buildSupportedResources(),
		Configuration:        cfg,
		ConfigurationExample: cfgExamples,
		Requirements: &rtypes.PluginRequirements{
			MinVultisigVersion: 1,
			SupportedChains:    getSupportedChainStrings(),
		},
	}, nil
}

func (s *SwapSpec) buildSupportedResources() []*rtypes.ResourcePattern {
	var resources []*rtypes.ResourcePattern
	for _, chain := range supportedChains {
		chainNameLower := strings.ToLower(chain.String())

		resources = append(resources, &rtypes.ResourcePattern{
			ResourcePath: &rtypes.ResourcePath{
				ChainId:    chainNameLower,
				ProtocolId: "swap",
				FunctionId: "",
				Full:       chainNameLower + ".swap",
			},
			Target: rtypes.TargetType_TARGET_TYPE_UNSPECIFIED,
			ParameterCapabilities: []*rtypes.ParameterConstraintCapability{
				{
					ParameterName:  "from_asset",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Required:       false,
				},
				{
					ParameterName:  "from_address",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Required:       true,
				},
				{
					ParameterName:  "from_amount",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Required:       true,
				},
				{
					ParameterName:  "to_chain",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Required:       true,
				},
				{
					ParameterName:  "to_asset",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Required:       false,
				},
				{
					ParameterName:  "to_address",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Required:       true,
				},
			},
			Required: true,
		})
	}

	return resources
}

func (s *SwapSpec) ValidatePluginPolicy(pol types.PluginPolicy) error {
	spec, err := s.GetRecipeSpecification()
	if err != nil {
		return fmt.Errorf("failed to get recipe spec: %w", err)
	}
	return plugin.ValidatePluginPolicy(pol, spec)
}
