package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/dca/internal/dca"
	"github.com/vultisig/dca/internal/health"
	"github.com/vultisig/dca/internal/metrics"
	"github.com/vultisig/verifier/plugin"
	plugin_config "github.com/vultisig/verifier/plugin/config"
	"github.com/vultisig/verifier/plugin/policy/policy_pg"
	"github.com/vultisig/verifier/plugin/scheduler"
	"github.com/vultisig/verifier/plugin/scheduler/scheduler_pg"
	"github.com/vultisig/verifier/plugin/tasks"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := logrus.New()
	logger.SetOutput(os.Stdout)
	logger.SetLevel(logrus.DebugLevel)

	cfg, err := newConfig()
	if err != nil {
		logger.Fatalf("failed to load config: %v", err)
	}

	// Start metrics server for scheduler
	metricsServer := metrics.StartMetricsServer(cfg.Metrics, []string{"scheduler"}, logger)
	defer func() {
		if metricsServer != nil {
			if err := metricsServer.Stop(ctx); err != nil {
				logger.Errorf("failed to stop metrics server: %v", err)
			}
		}
	}()

	redisConnOpt, err := asynq.ParseRedisURI(cfg.Redis.URI)
	if err != nil {
		logger.Fatalf("failed to parse redis URI: %v", err)
	}

	asynqClient := asynq.NewClient(redisConnOpt)

	pgPool, err := pgxpool.New(ctx, cfg.Postgres.DSN)
	if err != nil {
		logger.Fatalf("failed to initialize Postgres pool: %v", err)
	}

	policyStorage, err := plugin.WithMigrations(
		logger,
		pgPool,
		policy_pg.NewRepo,
		"policy/policy_pg/migrations",
	)
	if err != nil {
		logger.Fatalf("failed to initialize policy storage: %v", err)
	}

	schedulerStorage, err := plugin.WithMigrations(
		logger,
		pgPool,
		scheduler_pg.NewRepo,
		"scheduler/scheduler_pg/migrations",
	)
	if err != nil {
		logger.Fatalf("failed to initialize scheduler storage: %v", err)
	}

	worker := scheduler.NewWorker(
		logger,
		asynqClient,
		tasks.TypePluginTransaction,
		tasks.QUEUE_NAME,
		schedulerStorage,
		dca.NewSchedulerInterval(),
		policyStorage,
	)

	// Start scheduler metrics updater
	schedulerMetrics := metrics.NewSchedulerMetrics()
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		
		// Initial update
		updateSchedulerMetrics(ctx, pgPool, schedulerMetrics, logger)
		
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				updateSchedulerMetrics(ctx, pgPool, schedulerMetrics, logger)
			}
		}
	}()

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

type config struct {
	Postgres   plugin_config.Database
	Redis      plugin_config.Redis
	HealthPort int
	Metrics    metrics.Config
}

func newConfig() (config, error) {
	var cfg config
	err := envconfig.Process("", &cfg)
	if err != nil {
		return config{}, fmt.Errorf("failed to process env var: %w", err)
	}
	return cfg, nil
}

func updateSchedulerMetrics(ctx context.Context, pgPool *pgxpool.Pool, schedulerMetrics *metrics.SchedulerMetrics, logger *logrus.Logger) {
	// Count active policies
	var activeCount int
	err := pgPool.QueryRow(ctx, "SELECT COUNT(*) FROM plugin_policies WHERE active = true").Scan(&activeCount)
	if err != nil {
		logger.Errorf("Failed to count active policies: %v", err)
	} else {
		schedulerMetrics.UpdateActivePolicies(activeCount)
		logger.Debugf("Updated active policies count: %d", activeCount)
	}

	// Count stuck policies (policies with next_execution < now)
	var stuckCount int
	stuckQuery := `
		SELECT COUNT(*) 
		FROM scheduler s 
		JOIN plugin_policies p ON s.policy_id = p.id 
		WHERE p.active = true AND s.next_execution < NOW()`
	err = pgPool.QueryRow(ctx, stuckQuery).Scan(&stuckCount)
	if err != nil {
		logger.Errorf("Failed to count stuck policies: %v", err)
	} else {
		schedulerMetrics.UpdateStuckPolicies(stuckCount)
		logger.Debugf("Updated stuck policies count: %d", stuckCount)
	}
}
