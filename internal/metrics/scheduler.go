package metrics

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	// Total number of active policies
	schedulerActivePoliciesTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "dca",
			Subsystem: "scheduler",
			Name:      "active_policies_total",
			Help:      "Total number of active DCA policies",
		},
	)

	// Number of stuck policies (next_execution < now)
	schedulerStuckPoliciesTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "dca",
			Subsystem: "scheduler",
			Name:      "stuck_policies_total",
			Help:      "Number of policies with next_execution time in the past (stuck)",
		},
	)

	// Scheduler execution duration
	schedulerExecutionDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "dca",
			Subsystem: "scheduler",
			Name:      "execution_duration_seconds",
			Help:      "Duration of scheduler execution cycles",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Policies scheduled per execution cycle
	schedulerPoliciesScheduledTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "dca",
			Subsystem: "scheduler",
			Name:      "policies_scheduled_total",
			Help:      "Total number of policies scheduled for execution",
		},
		[]string{"status"}, // success, error
	)

	// Scheduler health check
	schedulerLastExecutionTimestamp = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "dca",
			Subsystem: "scheduler",
			Name:      "last_execution_timestamp",
			Help:      "Timestamp of last successful scheduler execution",
		},
	)
)

// SchedulerMetrics provides methods to update scheduler-related metrics
type SchedulerMetrics struct{}

// NewSchedulerMetrics creates a new instance of SchedulerMetrics
func NewSchedulerMetrics() *SchedulerMetrics {
	return &SchedulerMetrics{}
}

// UpdateActivePolicies updates the total number of active policies
func (sm *SchedulerMetrics) UpdateActivePolicies(count int) {
	schedulerActivePoliciesTotal.Set(float64(count))
}

// UpdateStuckPolicies updates the number of stuck policies
func (sm *SchedulerMetrics) UpdateStuckPolicies(count int) {
	schedulerStuckPoliciesTotal.Set(float64(count))
}

// RecordExecution records scheduler execution metrics
func (sm *SchedulerMetrics) RecordExecution(duration time.Duration, scheduled int, errors int) {
	schedulerExecutionDuration.Observe(duration.Seconds())
	schedulerPoliciesScheduledTotal.WithLabelValues("success").Add(float64(scheduled))
	if errors > 0 {
		schedulerPoliciesScheduledTotal.WithLabelValues("error").Add(float64(errors))
	}
	schedulerLastExecutionTimestamp.Set(float64(time.Now().Unix()))
}

// RecordSchedulingSuccess records a successful policy scheduling
func (sm *SchedulerMetrics) RecordSchedulingSuccess(count int) {
	schedulerPoliciesScheduledTotal.WithLabelValues("success").Add(float64(count))
}

// RecordSchedulingError records a scheduling error
func (sm *SchedulerMetrics) RecordSchedulingError() {
	schedulerPoliciesScheduledTotal.WithLabelValues("error").Inc()
}

// PolicyCounter interface for querying policy counts
type PolicyCounter interface {
	CountActivePolicies(ctx context.Context) (int, error)
	CountStuckPolicies(ctx context.Context) (int, error)
}

// StartMetricsUpdater starts a goroutine that periodically updates scheduler metrics
func (sm *SchedulerMetrics) StartMetricsUpdater(ctx context.Context, counter PolicyCounter) {
	ticker := time.NewTicker(30 * time.Second) // Update every 30 seconds
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sm.updatePolicyCounts(ctx, counter)
		}
	}
}

// updatePolicyCounts queries and updates the policy count metrics
func (sm *SchedulerMetrics) updatePolicyCounts(ctx context.Context, counter PolicyCounter) {
	// Update active policies count
	if activeCount, err := counter.CountActivePolicies(ctx); err == nil {
		sm.UpdateActivePolicies(activeCount)
	}
	
	// Update stuck policies count  
	if stuckCount, err := counter.CountStuckPolicies(ctx); err == nil {
		sm.UpdateStuckPolicies(stuckCount)
	}
}