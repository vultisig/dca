package main

import (
	"context"
	"fmt"

	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"

	"github.com/vultisig/dca/internal/dca"
	"github.com/vultisig/dca/internal/graceful"
	"github.com/vultisig/dca/internal/logging"
	"github.com/vultisig/dca/internal/metrics"
	"github.com/vultisig/verifier/plugin"
	plugin_config "github.com/vultisig/verifier/plugin/config"
	smetrics "github.com/vultisig/verifier/plugin/metrics"
	"github.com/vultisig/verifier/plugin/policy"
	"github.com/vultisig/verifier/plugin/policy/policy_pg"
	"github.com/vultisig/verifier/plugin/redis"
	"github.com/vultisig/verifier/plugin/scheduler/scheduler_pg"
	"github.com/vultisig/verifier/plugin/server"
	"github.com/vultisig/verifier/vault"
	"github.com/vultisig/verifier/vault_config"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, err := newConfig()
	if err != nil {
		logrus.Fatalf("failed to load config: %v", err)
	}

	logger := logging.NewLogger(cfg.LogFormat)

	// Start metrics server with HTTP metrics for server
	metricsServer := metrics.StartMetricsServer(cfg.Metrics, []string{metrics.ServiceHTTP}, logger)
	defer func() {
		if metricsServer != nil {
			if err := metricsServer.Stop(ctx); err != nil {
				logger.Errorf("failed to stop metrics server: %v", err)
			}
		}
	}()

	redisClient, err := redis.NewRedis(cfg.Redis)
	if err != nil {
		logger.Fatalf("failed to initialize Redis client: %v", err)
	}

	asynqConnOpt, err := asynq.ParseRedisURI(cfg.Redis.URI)
	if err != nil {
		logger.Fatalf("failed to parse redis URI: %v", err)
	}

	asynqClient := asynq.NewClient(asynqConnOpt)
	asynqInspector := asynq.NewInspector(asynqConnOpt)

	vaultStorage, err := vault.NewBlockStorageImp(cfg.BlockStorage)
	if err != nil {
		logger.Fatalf("failed to initialize Vault storage: %v", err)
	}

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

	policyService, err := policy.NewPolicyService(
		policyStorage,
		dca.NewSchedulerService(schedulerStorage),
		logger,
	)
	if err != nil {
		logger.Fatalf("failed to initialize policy service: %v", err)
	}

	var spec plugin.Spec
	switch cfg.Mode {
	case "send":
		spec = dca.NewSendSpec()
		logger.Info("Starting server in SEND mode")
	case "swap":
		spec = dca.NewSwapSpec()
		logger.Info("Starting server in SWAP mode")
	default:
		logger.Fatalf("invalid MODE: %s (must be 'send' or 'swap')", cfg.Mode)
	}

	// Add metrics middleware to default middlewares
	middlewares := append(server.DefaultMiddlewares(), metrics.HTTPMiddleware())

	srv := server.NewServer(
		cfg.Server,
		policyService,
		redisClient,
		vaultStorage,
		asynqClient,
		asynqInspector,
		spec,
		middlewares,
		smetrics.NewNilPluginServerMetrics(),
		logger,
	)

	if cfg.Verifier.Token != "" {
		srv.SetAuthMiddleware(server.NewAuth(cfg.Verifier.Token).Middleware)
	}

	go func() {
		sig := <-graceful.MakeSigintChan()
		logger.Infof("received exit signal: %v", sig)
		cancel()
	}()

	err = srv.Start(ctx)
	if err != nil {
		logger.Fatalf("failed to start server: %v", err)
	}
}

type config struct {
	Mode         string            `envconfig:"MODE" required:"true"`
	LogFormat    logging.LogFormat `envconfig:"LOG_FORMAT" default:"text"`
	Server       server.Config
	BlockStorage vault_config.BlockStorage
	Postgres     plugin_config.Database
	Redis        plugin_config.Redis
	Metrics      metrics.Config
	Verifier     plugin_config.Verifier
}

func newConfig() (config, error) {
	var cfg config
	err := envconfig.Process("", &cfg)
	if err != nil {
		return config{}, fmt.Errorf("failed to process env var: %w", err)
	}
	return cfg, nil
}
