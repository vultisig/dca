package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/app-recurring/internal/health"
	"github.com/vultisig/app-recurring/internal/logging"
	"github.com/vultisig/app-recurring/internal/metrics"
	"github.com/vultisig/verifier/plugin"
	"github.com/vultisig/verifier/plugin/tx_indexer"
	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/config"
	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/storage"
)

func main() {
	ctx := context.Background()

	cfg, err := newConfig()
	if err != nil {
		logrus.Fatalf("failed to load config: %v", err)
	}

	logger := logging.NewLogger(cfg.LogFormat)

	// Start metrics server for tx_indexer
	metricsServer := metrics.StartMetricsServer(cfg.Metrics, []string{metrics.ServiceTxIndexer}, logger)
	defer func() {
		if metricsServer != nil {
			if err := metricsServer.Stop(ctx); err != nil {
				logger.Errorf("failed to stop metrics server: %v", err)
			}
		}
	}()

	pgPool, err := pgxpool.New(ctx, cfg.Base.Database.DSN)
	if err != nil {
		logger.Fatalf("failed to initialize Postgres pool: %v", err)
	}

	txStorage, err := plugin.WithMigrations(
		logger,
		pgPool,
		storage.NewRepo,
		"tx_indexer/pkg/storage/migrations",
	)
	if err != nil {
		logger.Fatalf("failed to initialize tx_indexer storage: %v", err)
	}

	rpcs, err := tx_indexer.Rpcs(ctx, cfg.Base.Rpc)
	if err != nil {
		logger.Fatalf("failed to initialize RPCs: %v", err)
	}

	txMetrics := metrics.NewTxIndexerMetrics()

	worker := tx_indexer.NewWorker(
		logger,
		cfg.Base.Interval,
		cfg.Base.IterationTimeout,
		cfg.Base.MarkLostAfter,
		cfg.Base.Concurrency,
		txStorage,
		rpcs,
		txMetrics,
	)

	healthServer := health.New(cfg.HealthPort)
	go func() {
		er := healthServer.Start(ctx, logger)
		if er != nil {
			logger.Errorf("health server failed: %v", er)
		}
	}()

	// Set up signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		logger.Infof("Received signal %v, shutting down gracefully...", sig)
		cancel()
	}()

	// Start the worker in a goroutine
	workerDone := make(chan error, 1)
	go func() {
		workerDone <- worker.Run()
	}()

	// Wait for either worker completion or shutdown signal
	select {
	case err := <-workerDone:
		if err != nil {
			logger.Fatalf("worker failed: %v", err)
		}
	case <-ctx.Done():
		logger.Info("Shutdown signal received, exiting...")
		return
	}
}

type Config struct {
	LogFormat  logging.LogFormat
	Base       config.Config
	HealthPort int
	Metrics    metrics.Config
}

func newConfig() (Config, error) {
	var cfg Config
	err := envconfig.Process("", &cfg)
	if err != nil {
		return Config{}, fmt.Errorf("failed to process env var: %w", err)
	}
	return cfg, nil
}
