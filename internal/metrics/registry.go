package metrics

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/sirupsen/logrus"
)

// Service names for metrics registration
const (
	ServiceHTTP      = "http"
	ServiceScheduler = "scheduler"
	ServiceWorker    = "worker"
	ServiceTxIndexer = "tx_indexer"
)

// RegisterMetrics registers metrics for the specified services
func RegisterMetrics(services []string, logger *logrus.Logger) {
	// Always register Go and process metrics
	registerIfNotExists(collectors.NewGoCollector(), "go_collector", logger)
	registerIfNotExists(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}), "process_collector", logger)

	// Register service-specific metrics
	for _, service := range services {
		switch service {
		case ServiceHTTP:
			registerHTTPMetrics(logger)
		case ServiceScheduler:
			registerSchedulerMetrics(logger)
		case ServiceWorker:
			registerWorkerMetrics(logger)
		case ServiceTxIndexer:
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
	// Will implement when we add scheduler metrics
	logger.Debug("Scheduler metrics registration not yet implemented")
}

// registerWorkerMetrics registers worker-related metrics
func registerWorkerMetrics(logger *logrus.Logger) {
	registerIfNotExists(workerPolicyExecutionsByID, "worker_policy_executions_by_id", logger)
	registerIfNotExists(workerPolicyExecutionsTotal, "worker_policy_executions_total", logger)
	registerIfNotExists(workerSwapTransactionsTotal, "worker_swap_transactions_total", logger)
	registerIfNotExists(workerLastExecutionTimestamp, "worker_last_execution_timestamp", logger)
	registerIfNotExists(workerExecutionDuration, "worker_execution_duration", logger)
	registerIfNotExists(workerErrorsTotal, "worker_errors_total", logger)
	registerIfNotExists(workerTransactionProcessingDuration, "worker_transaction_processing_duration", logger)
}

// registerTxIndexerMetrics registers tx_indexer-related metrics
func registerTxIndexerMetrics(logger *logrus.Logger) {
	// Will implement when we add tx_indexer metrics
	logger.Debug("TX indexer metrics registration not yet implemented")
}