package recurring

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/vultisig/verifier/plugin/scheduler"
	"github.com/vultisig/verifier/types"
)

// parseDateTime parses a date string that can be either RFC3339 format or Unix milliseconds
func parseDateTime(dateStr string) (time.Time, error) {
	// Try RFC3339 first
	if t, err := time.Parse(time.RFC3339, dateStr); err == nil {
		return t, nil
	}

	// Try Unix milliseconds (e.g., "1765464900000")
	if ms, err := strconv.ParseInt(dateStr, 10, 64); err == nil {
		return time.UnixMilli(ms), nil
	}

	return time.Time{}, fmt.Errorf("invalid date format: %s (expected RFC3339 or Unix milliseconds)", dateStr)
}

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
