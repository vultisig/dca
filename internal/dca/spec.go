package dca

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kaptinlin/jsonschema"
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

	fromChainStr := cfg[fromChain].(string)
	fromChainTyped, err := common.FromString(fromChainStr)
	if err != nil {
		return nil, fmt.Errorf("unsupported chain: %s", fromChainStr)
	}

	rule, err := s.createSwapMetaRule(cfg, fromChainTyped)
	if err != nil {
		return nil, fmt.Errorf("failed to create swap meta rule: %w", err)
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

	var maxTxsPerWindow uint32
	switch {
	case fromChainTyped == common.Solana:
		maxTxsPerWindow = 3 // to fit ATA create + SPL token approve + Payload tx
	case fromChainTyped == common.XRP:
		maxTxsPerWindow = 1 // XRP doesn't need approvals, single tx for swaps
	case fromChainTyped.IsEvm():
		maxTxsPerWindow = 2 // to fit ERC20 approve + Payload tx
	default:
		maxTxsPerWindow = 1
	}

	return &rtypes.PolicySuggest{
		RateLimitWindow: conv.Ptr(rateLimitWindow),
		MaxTxsPerWindow: conv.Ptr(maxTxsPerWindow),
		Rules:           []*rtypes.Rule{rule},
	}, nil
}

func (s *Spec) createSwapMetaRule(cfg map[string]any, fromChainTyped common.Chain) (*rtypes.Rule, error) {
	fromChainLowercase := strings.ToLower(fromChainTyped.String())
	toAddressStr := cfg[toAddress].(string)
	fromAddressStr := cfg[fromAddress].(string)

	var fromAssetStr string
	if val, ok := cfg[fromAsset]; ok && val != nil {
		fromAssetStr, _ = val.(string)
	}

	var toAssetStr string
	if val, ok := cfg[toAsset]; ok && val != nil {
		toAssetStr, _ = val.(string)
	}

	return &rtypes.Rule{
		Resource: fromChainLowercase + ".swap",
		Effect:   rtypes.Effect_EFFECT_ALLOW,
		ParameterConstraints: []*rtypes.ParameterConstraint{
			{
				ParameterName: "from_asset",
				Constraint: &rtypes.Constraint{
					Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Value: &rtypes.Constraint_FixedValue{
						FixedValue: fromAssetStr,
					},
				},
			},
			{
				ParameterName: "from_address",
				Constraint: &rtypes.Constraint{
					Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Value: &rtypes.Constraint_FixedValue{
						FixedValue: fromAddressStr,
					},
				},
			},
			{
				ParameterName: "from_amount",
				Constraint: &rtypes.Constraint{
					Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Value: &rtypes.Constraint_FixedValue{
						FixedValue: cfg[fromAmount].(string),
					},
				},
			},
			{
				ParameterName: "to_chain",
				Constraint: &rtypes.Constraint{
					Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Value: &rtypes.Constraint_FixedValue{
						FixedValue: strings.ToLower(cfg[toChain].(string)),
					},
				},
			},
			{
				ParameterName: "to_asset",
				Constraint: &rtypes.Constraint{
					Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Value: &rtypes.Constraint_FixedValue{
						FixedValue: toAssetStr,
					},
				},
			},
			{
				ParameterName: "to_address",
				Constraint: &rtypes.Constraint{
					Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Value: &rtypes.Constraint_FixedValue{
						FixedValue: toAddressStr,
					},
				},
			},
		},
		Target: &rtypes.Target{
			TargetType: rtypes.TargetType_TARGET_TYPE_UNSPECIFIED,
			Target:     nil,
		},
	}, nil
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
			fromAddress: map[string]any{
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
			fromAddress,
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
				ProtocolId: "swap",
				FunctionId: "",
				Full:       chainNameLower + ".swap",
			},
			Target: rtypes.TargetType_TARGET_TYPE_ADDRESS,
			ParameterCapabilities: []*rtypes.ParameterConstraintCapability{
				{
					ParameterName:  "from_asset",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Required:       true,
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
					Required:       true,
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

func (s *Spec) ValidatePluginPolicy(pol types.PluginPolicy) error {
	spec, err := s.GetRecipeSpecification()
	if err != nil {
		return fmt.Errorf("failed to get recipe spec: %w", err)
	}
	return plugin.ValidatePluginPolicy(pol, spec)
}
