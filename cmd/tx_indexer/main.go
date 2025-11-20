package main

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/dca/internal/health"
	"github.com/vultisig/dca/internal/metrics"
	"github.com/vultisig/verifier/plugin"
	"github.com/vultisig/verifier/plugin/tx_indexer"
	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/config"
	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/storage"
)

func main() {
	ctx := context.Background()

	logger := logrus.New()
	logger.SetOutput(os.Stdout)
	logger.SetLevel(logrus.DebugLevel)

	cfg, err := newConfig()
	if err != nil {
		logger.Fatalf("failed to load config: %v", err)
	}

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

	err = worker.Run()
	if err != nil {
		logger.Fatalf("failed to run worker: %v", err)
	}
}

type Config struct {
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
