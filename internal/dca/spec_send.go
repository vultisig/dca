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

const (
	asset       = "asset"
	fromAddress = "fromAddress"
	toAddress   = "toAddress"
	amount      = "amount"
	memo        = "memo"
)

type SendSpec struct {
	plugin.Unimplemented
}

func NewSendSpec() *SendSpec {
	return &SendSpec{}
}

func (s *SendSpec) validateConfiguration(cfg map[string]any) error {
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

func (s *SendSpec) Suggest(cfg map[string]any) (*rtypes.PolicySuggest, error) {
	err := s.validateConfiguration(cfg)
	if err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	assetMap, ok := cfg[asset].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("'asset' must be an object")
	}

	chainStr, ok := assetMap["chain"].(string)
	if !ok {
		return nil, fmt.Errorf("'asset.chain' could not be empty")
	}

	chainTyped, err := common.FromString(chainStr)
	if err != nil {
		return nil, fmt.Errorf("unsupported chain: %s", chainStr)
	}

	rule, err := s.createSendMetaRule(cfg, chainTyped)
	if err != nil {
		return nil, fmt.Errorf("failed to create send meta rule: %w", err)
	}

	freq := cfg[frequency].(string)
	rateLimitWindow, err := getRateLimitWindow(freq)
	if err != nil {
		return nil, err
	}

	tokenStr := util.GetStr(assetMap, "token")
	maxTxsPerWindow := getMaxTxsForSend(chainTyped, tokenStr)

	return &rtypes.PolicySuggest{
		RateLimitWindow: conv.Ptr(rateLimitWindow),
		MaxTxsPerWindow: conv.Ptr(maxTxsPerWindow),
		Rules:           []*rtypes.Rule{rule},
	}, nil
}

func (s *SendSpec) createSendMetaRule(cfg map[string]any, chainTyped common.Chain) (*rtypes.Rule, error) {
	chainLowercase := strings.ToLower(chainTyped.String())

	assetMap, ok := cfg[asset].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("'asset' must be an object")
	}

	fromAddressStr, ok := cfg[fromAddress].(string)
	if !ok || fromAddressStr == "" {
		return nil, fmt.Errorf("'fromAddress' could not be empty")
	}

	toAddressStr, ok := cfg[toAddress].(string)
	if !ok || toAddressStr == "" {
		return nil, fmt.Errorf("'toAddress' could not be empty")
	}

	amountStr := util.GetStr(cfg, amount)
	if amountStr == "" {
		return nil, fmt.Errorf("'amount' could not be empty")
	}

	tokenStr := util.GetStr(assetMap, "token")

	return &rtypes.Rule{
		Resource: chainLowercase + ".send",
		Effect:   rtypes.Effect_EFFECT_ALLOW,
		ParameterConstraints: []*rtypes.ParameterConstraint{
			{
				ParameterName: "asset",
				Constraint: &rtypes.Constraint{
					Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Value: &rtypes.Constraint_FixedValue{
						FixedValue: tokenStr,
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
				ParameterName: "amount",
				Constraint: &rtypes.Constraint{
					Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Value: &rtypes.Constraint_FixedValue{
						FixedValue: amountStr,
					},
					Required: true,
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
			{
				ParameterName: "memo",
				Constraint: &rtypes.Constraint{
					Type:     rtypes.ConstraintType_CONSTRAINT_TYPE_ANY,
					Required: false,
				},
			},
		},
		Target: &rtypes.Target{
			TargetType: rtypes.TargetType_TARGET_TYPE_UNSPECIFIED,
		},
	}, nil
}

func (s *SendSpec) GetRecipeSpecification() (*rtypes.RecipeSchema, error) {
	assetDef := rjsonschema.NewAsset()

	cfg, err := plugin.RecipeConfiguration(map[string]any{
		"type":        "object",
		"definitions": rjsonschema.Definitions(),
		"properties": map[string]any{
			asset: map[string]any{
				"$ref": "#/definitions/" + assetDef.Name(),
			},
			fromAddress: map[string]any{
				"type": "string",
			},
			toAddress: map[string]any{
				"type": "string",
			},
			amount: map[string]any{
				"type": "string",
			},
			memo: map[string]any{
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
			asset,
			fromAddress,
			toAddress,
			amount,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build pb recipe config: %w", err)
	}

	cfgExample1, err := plugin.RecipeConfiguration(map[string]any{
		asset: map[string]any{
			"chain": "Bitcoin",
			"token": "",
		},
		amount:    "5000000",
		endDate:   "2026-12-25T00:00:00Z",
		frequency: daily,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build pb recipe config example1: %w", err)
	}
	cfgExample2, err := plugin.RecipeConfiguration(map[string]any{
		asset: map[string]any{
			"chain": "Ethereum",
			"token": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
		},
		amount:    "10000000",
		endDate:   "2026-12-25T00:00:00Z",
		frequency: daily,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build pb recipe config example2: %w", err)
	}
	cfgExamples := []*structpb.Struct{cfgExample1, cfgExample2}

	return &rtypes.RecipeSchema{
		Version:              1,
		PluginId:             PluginRecurringSends,
		PluginName:           "Recurring Sends",
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

func (s *SendSpec) buildSupportedResources() []*rtypes.ResourcePattern {
	var resources []*rtypes.ResourcePattern
	for _, chain := range supportedChains {
		chainNameLower := strings.ToLower(chain.String())

		resources = append(resources, &rtypes.ResourcePattern{
			ResourcePath: &rtypes.ResourcePath{
				ChainId:    chainNameLower,
				ProtocolId: "send",
				FunctionId: "Access to transaction signing",
				Full:       chainNameLower + ".send",
			},
			Target: rtypes.TargetType_TARGET_TYPE_UNSPECIFIED,
			ParameterCapabilities: []*rtypes.ParameterConstraintCapability{
				{
					ParameterName:  "asset",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Required:       false,
				},
				{
					ParameterName:  "from_address",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Required:       true,
				},
				{
					ParameterName:  "amount",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Required:       true,
				},
				{
					ParameterName:  "to_address",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Required:       true,
				},
				{
					ParameterName:  "memo",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_ANY,
					Required:       false,
				},
			},
			Required: true,
		})
	}

	return resources
}

func (s *SendSpec) ValidatePluginPolicy(pol types.PluginPolicy) error {
	spec, err := s.GetRecipeSpecification()
	if err != nil {
		return fmt.Errorf("failed to get recipe spec: %w", err)
	}
	return plugin.ValidatePluginPolicy(pol, spec)
}
