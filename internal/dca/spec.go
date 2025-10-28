package dca

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kaptinlin/jsonschema"
	"github.com/vultisig/dca/internal/util"
	rjsonschema "github.com/vultisig/recipes/jsonschema"
	evmsdk "github.com/vultisig/recipes/sdk/evm"
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
	common.Solana,
	common.XRP,
}

const (
	fromChain   = "fromChain"
	fromAsset   = "fromAsset"
	fromAmount  = "fromAmount"
	fromAddress = "fromAddress"

	toChain   = "toChain"
	toAsset   = "toAsset"
	toAddress = "toAddress"
)

const (
	endDate = "endDate"
)

const (
	frequency = "frequency"

	onetime  = "one-time"
	minutely = "minutely"
	hourly   = "hourly"
	daily    = "daily"
	weekly   = "weekly"
	biWeekly = "bi-weekly"
	monthly  = "monthly"
)

type Spec struct {
	plugin.Unimplemented
}

func NewSpec() *Spec {
	return &Spec{}
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

	fromAssetMap, ok := cfg[fromAsset].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("'fromAsset' must be an object")
	}

	fromChainStr, ok := fromAssetMap["chain"].(string)
	if !ok {
		return nil, fmt.Errorf("'fromAsset.chain' could not be empty")
	}

	fromChainTyped, err := common.FromString(fromChainStr)
	if err != nil {
		return nil, fmt.Errorf("unsupported chain: %s", fromChainStr)
	}

	toAssetMap, ok := cfg[toAsset].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("'toAsset' must be an object")
	}

	toChainStr, ok := toAssetMap["chain"].(string)
	if !ok {
		return nil, fmt.Errorf("'toAsset.chain' could not be empty")
	}

	fromAssetTokenStr := util.GetStr(fromAssetMap, "token")
	toAssetTokenStr := util.GetStr(toAssetMap, "token")

	fromAddressStr, ok := fromAssetMap["address"].(string)
	if !ok || fromAddressStr == "" {
		return nil, fmt.Errorf("'fromAsset.address' could not be empty")
	}

	toAddressStr, ok := toAssetMap["address"].(string)
	if !ok || toAddressStr == "" {
		return nil, fmt.Errorf("'toAsset.address' could not be empty")
	}

	isSend := fromChainStr == toChainStr && fromAssetTokenStr == toAssetTokenStr && fromAddressStr != toAddressStr

	var rule *rtypes.Rule
	if isSend {
		rule, err = s.createSendMetaRule(cfg, fromChainTyped)
		if err != nil {
			return nil, fmt.Errorf("failed to create send meta rule: %w", err)
		}
	} else {
		rule, err = s.createSwapMetaRule(cfg, fromChainTyped)
		if err != nil {
			return nil, fmt.Errorf("failed to create swap meta rule: %w", err)
		}
	}

	var rateLimitWindow uint32
	freq := cfg[frequency].(string)

	switch freq {
	case onetime:
		rateLimitWindow = 60
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

	var maxTxsPerWindow uint32
	if isSend {
		maxTxsPerWindow = 1
	} else {
		switch {
		case fromChainTyped == common.Solana:
			maxTxsPerWindow = 8
		case fromChainTyped == common.XRP:
			maxTxsPerWindow = 1
		case fromChainTyped.IsEvm():
			maxTxsPerWindow = 2
		default:
			maxTxsPerWindow = 1
		}
	}

	return &rtypes.PolicySuggest{
		RateLimitWindow: conv.Ptr(rateLimitWindow),
		MaxTxsPerWindow: conv.Ptr(maxTxsPerWindow),
		Rules:           []*rtypes.Rule{rule},
	}, nil
}

func (s *Spec) createSwapMetaRule(cfg map[string]any, fromChainTyped common.Chain) (*rtypes.Rule, error) {
	fromChainLowercase := strings.ToLower(fromChainTyped.String())

	fromAssetMap, ok := cfg[fromAsset].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("'fromAsset' must be an object")
	}

	toAssetMap, ok := cfg[toAsset].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("'toAsset' must be an object")
	}

	fromAddressStr, ok := fromAssetMap["address"].(string)
	if !ok || fromAddressStr == "" {
		return nil, fmt.Errorf("'fromAsset.address' could not be empty")
	}

	toAddressStr, ok := toAssetMap["address"].(string)
	if !ok || toAddressStr == "" {
		return nil, fmt.Errorf("'toAsset.address' could not be empty")
	}

	toChainStr, ok := toAssetMap["chain"].(string)
	if !ok || toChainStr == "" {
		return nil, fmt.Errorf("'toAsset.chain' could not be empty")
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

func (s *Spec) createSendMetaRule(cfg map[string]any, fromChainTyped common.Chain) (*rtypes.Rule, error) {
	fromChainLowercase := strings.ToLower(fromChainTyped.String())

	fromAssetMap, ok := cfg[fromAsset].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("'fromAsset' must be an object")
	}

	toAssetMap, ok := cfg[toAsset].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("'toAsset' must be an object")
	}

	fromAddressStr, ok := fromAssetMap["address"].(string)
	if !ok || fromAddressStr == "" {
		return nil, fmt.Errorf("'fromAsset.address' could not be empty")
	}

	toAddressStr, ok := toAssetMap["address"].(string)
	if !ok || toAddressStr == "" {
		return nil, fmt.Errorf("'toAsset.address' could not be empty")
	}

	fromAmountStr := util.GetStr(cfg, fromAmount)
	if fromAmountStr == "" {
		return nil, fmt.Errorf("'fromAmount' could not be empty")
	}

	fromAssetTokenStr := util.GetStr(fromAssetMap, "token")

	target := fromAssetTokenStr
	if target == "" {
		target = evmsdk.ZeroAddress.Hex()
	}

	return &rtypes.Rule{
		Resource: fromChainLowercase + ".send",
		Effect:   rtypes.Effect_EFFECT_ALLOW,
		ParameterConstraints: []*rtypes.ParameterConstraint{
			{
				ParameterName: "asset",
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
				ParameterName: "amount",
				Constraint: &rtypes.Constraint{
					Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Value: &rtypes.Constraint_FixedValue{
						FixedValue: fromAmountStr,
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
			TargetType: rtypes.TargetType_TARGET_TYPE_ADDRESS,
			Target: &rtypes.Target_Address{
				Address: target,
			},
		},
	}, nil
}

func (s *Spec) GetRecipeSpecification() (*rtypes.RecipeSchema, error) {
	var chains []any
	for _, chain := range supportedChains {
		chains = append(chains, chain.String())
	}

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

		resources = append(resources, &rtypes.ResourcePattern{
			ResourcePath: &rtypes.ResourcePath{
				ChainId:    chainNameLower,
				ProtocolId: "send",
				FunctionId: "",
				Full:       chainNameLower + ".send",
			},
			Target: rtypes.TargetType_TARGET_TYPE_ADDRESS,
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

func (s *Spec) ValidatePluginPolicy(pol types.PluginPolicy) error {
	spec, err := s.GetRecipeSpecification()
	if err != nil {
		return fmt.Errorf("failed to get recipe spec: %w", err)
	}
	return plugin.ValidatePluginPolicy(pol, spec)
}
