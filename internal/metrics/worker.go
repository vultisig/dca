package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vultisig/vultisig-go/common"
	evmsdk "github.com/vultisig/recipes/sdk/evm"
)

var (
	// Policy execution metrics by policy ID  
	workerPolicyExecutionsByID = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "dca",
			Subsystem: "worker",
			Name:      "policy_executions_by_id_total",
			Help:      "Total number of executions per policy ID",
		},
		[]string{"policy_id", "status"}, // policy_id, success/error
	)

	// Policy execution metrics
	workerPolicyExecutionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "dca",
			Subsystem: "worker",
			Name:      "policy_executions_total",
			Help:      "Total number of policy executions",
		},
		[]string{"status"}, // success, error
	)

	// Swap transaction metrics by asset
	workerSwapTransactionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "dca",
			Subsystem: "worker",
			Name:      "swap_transactions_total",
			Help:      "Total number of swap transactions",
		},
		[]string{"from_asset", "to_asset", "source_chain", "dest_chain", "status"}, // success, error
	)

	// Last execution timestamp
	workerLastExecutionTimestamp = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "dca",
			Subsystem: "worker",
			Name:      "last_execution_timestamp",
			Help:      "Timestamp of last policy execution",
		},
	)

	// Policy execution rate (executions per second over time window)
	workerExecutionDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "dca",
			Subsystem: "worker",
			Name:      "execution_duration_seconds",
			Help:      "Time taken to execute a policy",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Error rate tracking
	workerErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "dca",
			Subsystem: "worker",
			Name:      "errors_total",
			Help:      "Total number of worker errors",
		},
		[]string{"error_type"}, // validation, execution, signing, network
	)

	// Transaction processing metrics
	workerTransactionProcessingDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "dca",
			Subsystem: "worker",
			Name:      "transaction_processing_duration_seconds",
			Help:      "Time taken to process transactions",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"chain", "operation"}, // send, swap
	)
)

// WorkerMetrics provides methods to update worker-related metrics
type WorkerMetrics struct{}

// NewWorkerMetrics creates a new instance of WorkerMetrics
func NewWorkerMetrics() *WorkerMetrics {
	return &WorkerMetrics{}
}

// RecordPolicyExecution records a policy execution with policy ID
func (wm *WorkerMetrics) RecordPolicyExecution(policyID string, success bool, duration time.Duration) {
	status := "success"
	if !success {
		status = "error"
	}
	
	// Record by policy ID
	workerPolicyExecutionsByID.WithLabelValues(policyID, status).Inc()
	
	// Record overall totals
	workerPolicyExecutionsTotal.WithLabelValues(status).Inc()
	workerExecutionDuration.Observe(duration.Seconds())
	workerLastExecutionTimestamp.Set(float64(time.Now().Unix()))
}

// RecordSwapTransaction records a swap transaction
func (wm *WorkerMetrics) RecordSwapTransaction(fromAsset, toAsset, sourceChain, destChain string, success bool) {
	status := "success"
	if !success {
		status = "error"
	}
	
	workerSwapTransactionsTotal.WithLabelValues(fromAsset, toAsset, sourceChain, destChain, status).Inc()
}

// RecordError records different types of worker errors
func (wm *WorkerMetrics) RecordError(errorType string) {
	workerErrorsTotal.WithLabelValues(errorType).Inc()
}

// RecordTransactionProcessing records transaction processing time
func (wm *WorkerMetrics) RecordTransactionProcessing(chain, operation string, duration time.Duration) {
	workerTransactionProcessingDuration.WithLabelValues(chain, operation).Observe(duration.Seconds())
}

// RecordSwapTransactionWithFallback records a swap transaction with native asset fallback
func (wm *WorkerMetrics) RecordSwapTransactionWithFallback(fromAsset, toAsset, fromChain, toChain string, success bool) {
	if wm == nil {
		return
	}

	// Use native symbol if fromAsset is empty or zero address (means native token)
	fromAssetForMetrics := fromAsset
	if fromAssetForMetrics == "" || fromAssetForMetrics == evmsdk.ZeroAddress.String() {
		if fromChainTyped, err := common.FromString(fromChain); err == nil {
			if nativeSymbol, err := fromChainTyped.NativeSymbol(); err == nil {
				fromAssetForMetrics = nativeSymbol
			} else {
				fromAssetForMetrics = fromChain
			}
		} else {
			fromAssetForMetrics = fromChain
		}
	}

	// Use native symbol if toAsset is empty or zero address (means native token)
	toAssetForMetrics := toAsset
	if toAssetForMetrics == "" || toAssetForMetrics == evmsdk.ZeroAddress.String() {
		if toChainTyped, err := common.FromString(toChain); err == nil {
			if nativeSymbol, err := toChainTyped.NativeSymbol(); err == nil {
				toAssetForMetrics = nativeSymbol
			} else {
				toAssetForMetrics = toChain
			}
		} else {
			toAssetForMetrics = toChain
		}
	}

	wm.RecordSwapTransaction(fromAssetForMetrics, toAssetForMetrics, fromChain, toChain, success)
}

// Error type constants for consistent labeling
const (
	ErrorTypeValidation = "validation"
	ErrorTypeExecution  = "execution"
	ErrorTypeSigning    = "signing"
	ErrorTypeNetwork    = "network"
)