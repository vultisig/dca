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
	return s.repo.Create(ctx, policy.ID, time.Now())
}

func (s *SchedulerService) Update(_ context.Context, _, _ types.PluginPolicy) error {
	return errors.New("recurring policy couldn't be changed")
}

func (s *SchedulerService) Delete(ctx context.Context, policyID uuid.UUID) error {
	return s.repo.Delete(ctx, policyID)
}
