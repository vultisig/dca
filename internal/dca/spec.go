package dca

import (
	"fmt"

	rtypes "github.com/vultisig/recipes/types"
	"github.com/vultisig/verifier/plugin"
	"github.com/vultisig/verifier/types"
)

const (
	startDate = "startDate"
)

const (
	frequency = "frequency"

	daily    = "daily"
	weekly   = "weekly"
	biWeekly = "bi-weekly"
	monthly  = "monthly"
)

type Spec struct{}

func (s *Spec) GetRecipeSpecification() (*rtypes.RecipeSchema, error) {
	return &rtypes.RecipeSchema{
		// TODO
	}, nil
}

func (s *Spec) ValidatePluginPolicy(pol types.PluginPolicy) error {
	spec, err := s.GetRecipeSpecification()
	if err != nil {
		return fmt.Errorf("failed to get recipe spec: %w", err)
	}
	return plugin.ValidatePluginPolicy(pol, spec)
}
