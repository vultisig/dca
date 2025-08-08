package dca

import (
	"fmt"

	rtypes "github.com/vultisig/recipes/types"
	"github.com/vultisig/verifier/plugin"
	"github.com/vultisig/verifier/types"
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

type Spec struct{}

func (s *Spec) GetRecipeSpecification() (*rtypes.RecipeSchema, error) {
	cfg, err := plugin.RecipeConfiguration(map[string]any{
		"type": "object",
		"properties": map[string]any{
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
						SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_MIN,
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
						SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_MIN,
						Required:       true,
					},
				},
				Required: true,
			},
		},
		Configuration: cfg,
		Requirements: &rtypes.PluginRequirements{
			MinVultisigVersion: 1,
			SupportedChains:    []string{"ethereum"},
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
