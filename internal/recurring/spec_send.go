package recurring

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kaptinlin/jsonschema"
	"github.com/vultisig/app-recurring/internal/util"
	rjsonschema "github.com/vultisig/recipes/jsonschema"
	solanasdk "github.com/vultisig/recipes/sdk/solana"
	rtypes "github.com/vultisig/recipes/types"
	"github.com/vultisig/verifier/plugin"
	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/conv"
	"github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/common"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	recipients = "recipients"
	memo       = "memo"
)

type SendSpec struct {
	plugin.Unimplemented
	solanaSDK *solanasdk.SDK
}

func NewSendSpec(solanaSDK *solanasdk.SDK) *SendSpec {
	return &SendSpec{
		solanaSDK: solanaSDK,
	}
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

func (s *SendSpec) Suggest(ctx context.Context, cfg map[string]any) (*rtypes.PolicySuggest, error) {
	err := s.validateConfiguration(cfg)
	if err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	// Parse top-level asset (shared by all recipients)
	assetMap, ok := cfg["asset"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("'asset' must be an object")
	}

	chainStr, ok := assetMap["chain"].(string)
	if !ok || chainStr == "" {
		return nil, fmt.Errorf("'asset.chain' could not be empty")
	}

	chainTyped, err := common.FromString(chainStr)
	if err != nil {
		return nil, fmt.Errorf("unsupported chain: %s", chainStr)
	}

	// Get recipients count for rate limiting
	recipientsList, ok := cfg[recipients].([]any)
	if !ok || len(recipientsList) == 0 {
		return nil, fmt.Errorf("'recipients' must be a non-empty array")
	}
	recipientCount := len(recipientsList)

	// Query token program for Solana chains.
	// Solana is a special case: Token-2022 tokens use a different program ID than legacy SPL tokens,
	// and this affects ATA derivation. We cannot determine the token program from static config alone -
	// we must query the mint account on-chain to check which program owns it.
	var tokenProgram string
	if chainTyped == common.Solana && s.solanaSDK != nil {
		tokenStr := util.GetStr(assetMap, "token")
		tokenProgram, err = s.solanaSDK.GetTokenProgram(ctx, tokenStr)
		if err != nil {
			return nil, fmt.Errorf("failed to get token program: %w", err)
		}
	}

	// Generate rules for all recipients
	rules, err := s.createSendMetaRules(cfg, chainTyped, tokenProgram)
	if err != nil {
		return nil, fmt.Errorf("failed to create send meta rules: %w", err)
	}

	freq := cfg[frequency].(string)
	rateLimitWindow, err := getRateLimitWindow(freq)
	if err != nil {
		return nil, err
	}

	tokenStr := util.GetStr(assetMap, "token")
	maxTxsPerWindow := getMaxTxsForSend(chainTyped, tokenStr, recipientCount)

	return &rtypes.PolicySuggest{
		RateLimitWindow: conv.Ptr(rateLimitWindow),
		MaxTxsPerWindow: conv.Ptr(maxTxsPerWindow),
		Rules:           rules,
	}, nil
}

// createSendMetaRules generates a rule for each recipient in the recipients list
func (s *SendSpec) createSendMetaRules(cfg map[string]any, chainTyped common.Chain, tokenProgram string) ([]*rtypes.Rule, error) {
	chainLowercase := strings.ToLower(chainTyped.String())

	// Get top-level asset (shared by all recipients)
	assetMap, ok := cfg["asset"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("'asset' must be an object")
	}

	// asset.address = sender's address (fromAddress)
	fromAddressStr, ok := assetMap["address"].(string)
	if !ok || fromAddressStr == "" {
		return nil, fmt.Errorf("'asset.address' (sender address) could not be empty")
	}

	tokenStr := util.GetStr(assetMap, "token")

	recipientsList, ok := cfg[recipients].([]any)
	if !ok || len(recipientsList) == 0 {
		return nil, fmt.Errorf("'recipients' must be a non-empty array")
	}

	var rules []*rtypes.Rule

	for i, recipientItem := range recipientsList {
		recipient, ok := recipientItem.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("'recipients[%d]' must be an object", i)
		}

		toAddressStr, ok := recipient["toAddress"].(string)
		if !ok || toAddressStr == "" {
			return nil, fmt.Errorf("'recipients[%d].toAddress' could not be empty", i)
		}

		amountStr := util.GetStr(recipient, "amount")
		if amountStr == "" {
			return nil, fmt.Errorf("'recipients[%d].amount' could not be empty", i)
		}

		constraints := []*rtypes.ParameterConstraint{
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
		}

		// Add memo constraint only if user configured a memo
		// This is used for CEX transfers and memo-based chains like XRP
		memoStr := util.GetStr(cfg, memo)
		if memoStr != "" {
			constraints = append(constraints, &rtypes.ParameterConstraint{
				ParameterName: "memo",
				Constraint: &rtypes.Constraint{
					Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Value: &rtypes.Constraint_FixedValue{
						FixedValue: memoStr,
					},
					Required: false,
				},
			})
		}

		// Add token program constraint for Solana
		if tokenProgram != "" {
			constraints = append(constraints, &rtypes.ParameterConstraint{
				ParameterName: "token_program",
				Constraint: &rtypes.Constraint{
					Type: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
					Value: &rtypes.Constraint_FixedValue{
						FixedValue: tokenProgram,
					},
					Required: false,
				},
			})
		}

		rule := &rtypes.Rule{
			Resource:             chainLowercase + ".send",
			Effect:               rtypes.Effect_EFFECT_ALLOW,
			ParameterConstraints: constraints,
			Target: &rtypes.Target{
				TargetType: rtypes.TargetType_TARGET_TYPE_UNSPECIFIED,
			},
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

func (s *SendSpec) GetRecipeSpecification() (*rtypes.RecipeSchema, error) {
	assetDef := rjsonschema.NewAsset()

	cfg, err := plugin.RecipeConfiguration(map[string]any{
		"type":        "object",
		"definitions": rjsonschema.Definitions(),
		"properties": map[string]any{
			"asset": map[string]any{
				"$ref":        "#/definitions/" + assetDef.Name(),
				"description": "Asset to send (chain, token, address=sender). Shared by all recipients.",
			},
			recipients: map[string]any{
				"type":     "array",
				"minItems": 1,
				"maxItems": 10,
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"toAddress": map[string]any{
							"type":        "string",
							"description": "Recipient address",
						},
						"amount": map[string]any{
							"type":        "string",
							"description": "Amount to send",
						},
						"alias": map[string]any{
							"type":        "string",
							"description": "Optional alias for the recipient",
						},
					},
					"required": []any{"toAddress", "amount"},
				},
			},
			memo: map[string]any{
				"type": "string",
			},
			startDate: map[string]any{
				"type":   "string",
				"format": "date-time",
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
			"asset",
			frequency,
			recipients,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build pb recipe config: %w", err)
	}

	cfgExample1, err := plugin.RecipeConfiguration(map[string]any{
		"asset": map[string]any{
			"chain":   "Bitcoin",
			"token":   "",
			"address": "",
		},
		recipients: []any{
			map[string]any{
				"toAddress": "",
				"amount":    "0.05",
			},
		},
		endDate:   "2026-12-31T12:00:00Z",
		frequency: daily,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build pb recipe config example1: %w", err)
	}
	cfgExample2, err := plugin.RecipeConfiguration(map[string]any{
		"asset": map[string]any{
			"chain":   "Ethereum",
			"token":   "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
			"address": "",
		},
		recipients: []any{
			map[string]any{
				"toAddress": "",
				"amount":    "10",
			},
		},
		endDate:   "2026-12-31T12:00:00Z",
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
		Permissions: []*rtypes.Permission{
			{
				Id:          "transaction_signing",
				Label:       "Access to transaction signing",
				Description: "The app can initiate transactions to send assets in your Vault",
			},
			{
				Id:          "fee_deduction",
				Label:       "Fee deduction authorization",
				Description: "The app can automatically deduct incurred fees.",
			},
			{
				Id:          "balance_visibility",
				Label:       "Vault balance visibility",
				Description: "The app can view Vault balances",
			},
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
				{
					ParameterName:  "token_program",
					SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
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
