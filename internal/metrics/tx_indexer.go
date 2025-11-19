package metrics

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	// On-chain status distribution per chain
	txIndexerOnchainStatusTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "dca",
			Subsystem: "tx_indexer",
			Name:      "onchain_status_total",
			Help:      "Total number of transactions by on-chain status per chain",
		},
		[]string{"chain", "status"}, // chain name, PENDING/SUCCESS/FAIL
	)

	// Transaction processing status distribution per chain
	txIndexerTransactionsProcessedTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "dca",
			Subsystem: "tx_indexer",
			Name:      "transactions_processed_total",
			Help:      "Total number of transactions by processing status per chain",
		},
		[]string{"chain", "status"}, // chain name, PROPOSED/VERIFIED/SIGNED
	)

	// Lost transactions per chain
	txIndexerLostTransactionsTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "dca",
			Subsystem: "tx_indexer",
			Name:      "lost_transactions_total",
			Help:      "Total number of lost transactions per chain",
		},
		[]string{"chain"}, // chain name
	)

	// Processing iteration metrics
	txIndexerProcessingDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "dca",
			Subsystem: "tx_indexer",
			Name:      "processing_duration_seconds",
			Help:      "Duration of tx_indexer processing iterations",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// Processing rate (transactions processed per iteration)
	txIndexerTransactionsPerIteration = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "dca",
			Subsystem: "tx_indexer",
			Name:      "transactions_per_iteration",
			Help:      "Number of transactions processed in last iteration",
		},
	)

	// Last processing timestamp
	txIndexerLastProcessingTimestamp = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "dca",
			Subsystem: "tx_indexer",
			Name:      "last_processing_timestamp",
			Help:      "Timestamp of last successful tx_indexer processing iteration",
		},
	)
)

// TxIndexerMetrics provides methods to update tx_indexer-related metrics
type TxIndexerMetrics struct{}

// NewTxIndexerMetrics creates a new instance of TxIndexerMetrics
func NewTxIndexerMetrics() *TxIndexerMetrics {
	return &TxIndexerMetrics{}
}

// UpdateOnchainStatus updates the on-chain status counts per chain
func (tim *TxIndexerMetrics) UpdateOnchainStatus(chain, status string, count int) {
	txIndexerOnchainStatusTotal.WithLabelValues(chain, status).Set(float64(count))
}

// UpdateProcessingStatus updates the processing status counts per chain
func (tim *TxIndexerMetrics) UpdateProcessingStatus(chain, status string, count int) {
	txIndexerTransactionsProcessedTotal.WithLabelValues(chain, status).Set(float64(count))
}

// UpdateLostTransactions updates the lost transaction counts per chain
func (tim *TxIndexerMetrics) UpdateLostTransactions(chain string, count int) {
	txIndexerLostTransactionsTotal.WithLabelValues(chain).Set(float64(count))
}

// RecordProcessingIteration records metrics for a processing iteration
func (tim *TxIndexerMetrics) RecordProcessingIteration(duration time.Duration, transactionCount int) {
	txIndexerProcessingDuration.Observe(duration.Seconds())
	txIndexerTransactionsPerIteration.Set(float64(transactionCount))
	txIndexerLastProcessingTimestamp.Set(float64(time.Now().Unix()))
}

// TxStatusCounter interface for querying transaction status counts
type TxStatusCounter interface {
	CountOnchainStatus(ctx context.Context) (map[string]map[string]int, error)      // chain -> status -> count
	CountProcessingStatus(ctx context.Context) (map[string]map[string]int, error)   // chain -> status -> count
	CountLostTransactions(ctx context.Context) (map[string]int, error)              // chain -> count
}