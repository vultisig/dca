package metrics

import (
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
)

// SchedulerMetrics provides methods to update scheduler-related metrics
// Implements the verifier SchedulerMetrics interface
type SchedulerMetrics struct{}

// NewSchedulerMetrics creates a new instance of SchedulerMetrics
func NewSchedulerMetrics() *SchedulerMetrics {
	return &SchedulerMetrics{}
}

// SetActivePolicies sets the total number of active policies (verifier interface)
func (sm *SchedulerMetrics) SetActivePolicies(count float64) {
	schedulerActivePoliciesTotal.Set(count)
}

// SetStuckPolicies sets the number of policies with next_execution < now (verifier interface)
func (sm *SchedulerMetrics) SetStuckPolicies(count float64) {
	schedulerStuckPoliciesTotal.Set(count)
}