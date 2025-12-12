package recurring

import (
	"fmt"
	"strconv"
	"time"

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

type Interval struct {
}

func NewSchedulerInterval() *Interval {
	return &Interval{}
}

func (i *Interval) FromNowWhenNext(policy types.PluginPolicy) (time.Time, error) {
	recipe, err := policy.GetRecipe()
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to unpack recipe: %w", err)
	}

	cfg := recipe.GetConfiguration().GetFields()

	if endDateField, exists := cfg[endDate]; exists {
		endDateStr := endDateField.GetStringValue()
		if endDateStr != "" {
			endTime, er := parseDateTime(endDateStr)
			if er != nil {
				return time.Time{}, fmt.Errorf("failed to parse endDate '%s': %w", endDateStr, er)
			}
			if time.Now().After(endTime) {
				return time.Time{}, nil
			}
		}
	}

	var next time.Time
	freq := cfg[frequency].GetStringValue()
	switch freq {
	case onetime:
		return time.Time{}, nil
	case minutely:
		next = time.Now().Add(time.Minute)
	case hourly:
		next = time.Now().Add(time.Hour)
	case daily:
		next = time.Now().AddDate(0, 0, 1)
	case weekly:
		next = time.Now().AddDate(0, 0, 7)
	case biWeekly:
		next = time.Now().AddDate(0, 0, 14)
	case monthly:
		next = time.Now().AddDate(0, 1, 0)
	default:
		return time.Time{}, fmt.Errorf("unknown frequency: %s", freq)
	}

	if endDateField, exists := cfg[endDate]; exists {
		endDateStr := endDateField.GetStringValue()
		if endDateStr != "" {
			endTime, er := parseDateTime(endDateStr)
			if er != nil {
				return time.Time{}, fmt.Errorf("failed to parse endDate '%s': %w", endDateStr, er)
			}
			if next.After(endTime) {
				return time.Time{}, nil
			}
		}
	}

	return next, nil
}
