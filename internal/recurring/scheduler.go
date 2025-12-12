package recurring

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/vultisig/verifier/plugin/scheduler"
	"github.com/vultisig/verifier/types"
)

type SchedulerService struct {
	repo scheduler.Storage
}

func NewSchedulerService(repo scheduler.Storage) *SchedulerService {
	return &SchedulerService{
		repo: repo,
	}
}

func (s *SchedulerService) Create(ctx context.Context, policy types.PluginPolicy) error {
	initialTime := time.Now()

	recipe, err := policy.GetRecipe()
	if err == nil {
		cfg := recipe.GetConfiguration().GetFields()
		if startDateField, exists := cfg[startDate]; exists {
			startDateStr := startDateField.GetStringValue()
			if startDateStr != "" {
				startTime, err := parseDateTime(startDateStr)
				if err == nil && startTime.After(time.Now()) {
					initialTime = startTime
				}
			}
		}
	}

	return s.repo.Create(ctx, policy.ID, initialTime)
}

func (s *SchedulerService) Update(_ context.Context, _, _ types.PluginPolicy) error {
	return errors.New("recurring policy couldn't be changed")
}

func (s *SchedulerService) Delete(ctx context.Context, policyID uuid.UUID) error {
	return s.repo.Delete(ctx, policyID)
}
