package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vultisig/verifier/plugin/metrics"
	"github.com/vultisig/vultisig-go/common"
)

var (
	// Transaction status tracking (used by RecordTransactionStatus)
	txIndexerTransactionStatus = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "dca",
			Subsystem: "tx_indexer",
			Name:      "transaction_status_total",
			Help:      "Total number of transaction status changes by chain and status",
		},
		[]string{"chain", "status"}, // chain name, PENDING/SUCCESS/FAIL
	)

	// Processing attempts (used by RecordProcessing)
	txIndexerProcessingTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "dca",
			Subsystem: "tx_indexer",
			Name:      "processing_total",
			Help:      "Total number of processing attempts by chain",
		},
		[]string{"chain"},
	)

	// Iteration duration by chain (used by RecordIterationDuration)
	txIndexerIterationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "dca",
			Subsystem: "tx_indexer",
			Name:      "iteration_duration_seconds",
			Help:      "Duration of processing iterations by chain",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"chain"},
	)

	// Last processing timestamp (used by SetLastProcessingTimestamp)
	txIndexerLastProcessingTimestamp = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "dca",
			Subsystem: "tx_indexer",
			Name:      "last_processing_timestamp",
			Help:      "Timestamp of last processing iteration",
		},
	)

	// Active transactions (used by SetActiveTransactions)
	txIndexerActiveTransactions = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "dca",
			Subsystem: "tx_indexer",
			Name:      "active_transactions",
			Help:      "Number of active transactions by chain and status",
		},
		[]string{"chain", "status"},
	)

	// Processing errors (used by RecordProcessingError)
	txIndexerProcessingErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "dca",
			Subsystem: "tx_indexer",
			Name:      "processing_errors_total",
			Help:      "Total number of processing errors by chain and type",
		},
		[]string{"chain", "error_type"},
	)

	// RPC errors (used by RecordRPCError)
	txIndexerRPCErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "dca",
			Subsystem: "tx_indexer",
			Name:      "rpc_errors_total",
			Help:      "Total number of RPC errors by chain",
		},
		[]string{"chain"},
	)

	// Chain height (used by SetChainHeight)
	txIndexerChainHeight = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "dca",
			Subsystem: "tx_indexer",
			Name:      "chain_height",
			Help:      "Current chain height by chain",
		},
		[]string{"chain"},
	)
)

// TxIndexerMetrics provides methods to update tx_indexer-related metrics
type TxIndexerMetrics struct{}

// NewTxIndexerMetrics creates a new instance of TxIndexerMetrics
func NewTxIndexerMetrics() *TxIndexerMetrics {
	return &TxIndexerMetrics{}
}

// Verifier interface implementation
// Register registers all TX indexer metrics with the provided registry
func (tim *TxIndexerMetrics) Register(registry metrics.Registry) {
	if reg, ok := registry.(prometheus.Registerer); ok {
		reg.MustRegister(
			txIndexerTransactionStatus,
			txIndexerProcessingTotal,
			txIndexerIterationDuration,
			txIndexerLastProcessingTimestamp,
			txIndexerActiveTransactions,
			txIndexerProcessingErrors,
			txIndexerRPCErrors,
			txIndexerChainHeight,
		)
	}
}

// RecordTransactionStatus records a transaction status change
func (tim *TxIndexerMetrics) RecordTransactionStatus(chain common.Chain, status string) {
	txIndexerTransactionStatus.WithLabelValues(chain.String(), status).Inc()
}

// RecordProcessing records a processing attempt
func (tim *TxIndexerMetrics) RecordProcessing(chain common.Chain) {
	txIndexerProcessingTotal.WithLabelValues(chain.String()).Inc()
}

// RecordIterationDuration records the duration of a processing iteration
func (tim *TxIndexerMetrics) RecordIterationDuration(chain common.Chain, duration float64) {
	txIndexerIterationDuration.WithLabelValues(chain.String()).Observe(duration)
}

// SetLastProcessingTimestamp sets the timestamp of the last processing iteration
func (tim *TxIndexerMetrics) SetLastProcessingTimestamp(timestamp float64) {
	txIndexerLastProcessingTimestamp.Set(timestamp)
}

// SetActiveTransactions sets the number of active transactions
func (tim *TxIndexerMetrics) SetActiveTransactions(chain common.Chain, status string, count float64) {
	txIndexerActiveTransactions.WithLabelValues(chain.String(), status).Set(count)
}

// RecordProcessingError records a processing error
func (tim *TxIndexerMetrics) RecordProcessingError(chain common.Chain, errorType string) {
	txIndexerProcessingErrors.WithLabelValues(chain.String(), errorType).Inc()
}

// RecordRPCError records an RPC error
func (tim *TxIndexerMetrics) RecordRPCError(chain common.Chain) {
	txIndexerRPCErrors.WithLabelValues(chain.String()).Inc()
}

// SetChainHeight sets the current chain height
func (tim *TxIndexerMetrics) SetChainHeight(chain common.Chain, height float64) {
	txIndexerChainHeight.WithLabelValues(chain.String()).Set(height)
}
