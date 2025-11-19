package metrics

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/sirupsen/logrus"
)

// RegisterMetrics registers metrics for the specified services
func RegisterMetrics(services []string, logger *logrus.Logger) {
	// Always register Go and process metrics
	registerIfNotExists(collectors.NewGoCollector(), "go_collector", logger)
	registerIfNotExists(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}), "process_collector", logger)

	// Register service-specific metrics
	for _, service := range services {
		switch service {
		case "http":
			registerHTTPMetrics(logger)
		case "scheduler":
			registerSchedulerMetrics(logger)
		case "worker":
			registerWorkerMetrics(logger)
		case "tx_indexer":
			registerTxIndexerMetrics(logger)
		default:
			logger.Warnf("Unknown service type for metrics registration: %s", service)
		}
	}
}

// registerIfNotExists registers a collector if it's not already registered
func registerIfNotExists(collector prometheus.Collector, name string, logger *logrus.Logger) {
	if err := prometheus.Register(collector); err != nil {
		var alreadyRegErr prometheus.AlreadyRegisteredError
		if errors.As(err, &alreadyRegErr) {
			// This is expected on restart/reload - just debug log
			logger.Debugf("%s already registered", name)
		} else {
			// This is a real problem (descriptor mismatch, etc.) - fatal error
			logger.Errorf("Failed to register %s: %v", name, err)
		}
	}
}

// registerHTTPMetrics registers HTTP-related metrics
func registerHTTPMetrics(logger *logrus.Logger) {
	registerIfNotExists(httpRequestsTotal, "http_requests_total", logger)
	registerIfNotExists(httpRequestDuration, "http_request_duration", logger)
	registerIfNotExists(httpErrorsTotal, "http_errors_total", logger)
}

// registerSchedulerMetrics registers scheduler-related metrics
func registerSchedulerMetrics(logger *logrus.Logger) {
	registerIfNotExists(schedulerActivePoliciesTotal, "scheduler_active_policies_total", logger)
	registerIfNotExists(schedulerStuckPoliciesTotal, "scheduler_stuck_policies_total", logger)
	registerIfNotExists(schedulerExecutionDuration, "scheduler_execution_duration", logger)
	registerIfNotExists(schedulerPoliciesScheduledTotal, "scheduler_policies_scheduled_total", logger)
	registerIfNotExists(schedulerLastExecutionTimestamp, "scheduler_last_execution_timestamp", logger)
}

// registerWorkerMetrics registers worker-related metrics
func registerWorkerMetrics(logger *logrus.Logger) {
	// Will implement when we add worker metrics
	logger.Debug("Worker metrics registration not yet implemented")
}

// registerTxIndexerMetrics registers tx_indexer-related metrics
func registerTxIndexerMetrics(logger *logrus.Logger) {
	// Will implement when we add tx_indexer metrics
	logger.Debug("TX indexer metrics registration not yet implemented")
}