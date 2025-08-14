package dca

import (
	"fmt"
	"time"

	"github.com/vultisig/verifier/types"
)

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
			endTime, er := time.Parse(time.RFC3339, endDateStr)
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
			endTime, er := time.Parse(time.RFC3339, endDateStr)
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
