package main

import (
	"context"
	"fmt"
	"net"
	"os"

	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/dca/internal/dca"
	"github.com/vultisig/dca/internal/graceful"
	"github.com/vultisig/recipes/common"
	"github.com/vultisig/verifier/plugin"
	plugin_config "github.com/vultisig/verifier/plugin/config"
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

	logger := logrus.New()
	logger.SetOutput(os.Stdout)
	logger.SetLevel(logrus.DebugLevel)

	cfg, err := newConfig()
	if err != nil {
		logger.Fatalf("failed to load config: %v", err)
	}

	redisClient, err := redis.NewRedis(cfg.Redis)
	if err != nil {
		logger.Fatalf("failed to initialize Redis client: %v", err)
	}

	asynqClient := asynq.NewClient(asynq.RedisClientOpt{
		Addr:     net.JoinHostPort(cfg.Redis.Host, cfg.Redis.Port),
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})
	asynqInspector := asynq.NewInspector(asynq.RedisClientOpt{
		Addr:     net.JoinHostPort(cfg.Redis.Host, cfg.Redis.Port),
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})

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

	uniswapRouters := map[common.Chain]ecommon.Address{
		common.Ethereum:  ecommon.HexToAddress(cfg.Uniswap.RouterV2.Ethereum),
		common.Arbitrum:  ecommon.HexToAddress(cfg.Uniswap.RouterV2.Arbitrum),
		common.Avalanche: ecommon.HexToAddress(cfg.Uniswap.RouterV2.Avalanche),
		common.BscChain:  ecommon.HexToAddress(cfg.Uniswap.RouterV2.BSC),
		common.Base:      ecommon.HexToAddress(cfg.Uniswap.RouterV2.Base),
		common.Blast:     ecommon.HexToAddress(cfg.Uniswap.RouterV2.Blast),
		common.Optimism:  ecommon.HexToAddress(cfg.Uniswap.RouterV2.Optimism),
		common.Polygon:   ecommon.HexToAddress(cfg.Uniswap.RouterV2.Polygon),
	}

	srv := server.NewServer(
		cfg.Server,
		policyService,
		redisClient,
		vaultStorage,
		asynqClient,
		asynqInspector,
		dca.NewSpec(uniswapRouters),
		server.DefaultMiddlewares(),
	)

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
	Server       server.Config
	BlockStorage vault_config.BlockStorage
	Postgres     plugin_config.Database
	Redis        plugin_config.Redis
	Uniswap      uniswapConfig
}

type uniswapConfig struct {
	RouterV2 router
}

type router struct {
	Ethereum  string
	Arbitrum  string
	Avalanche string
	BSC       string
	Base      string
	Blast     string
	Optimism  string
	Polygon   string
}

func newConfig() (config, error) {
	var cfg config
	err := envconfig.Process("", &cfg)
	if err != nil {
		return config{}, fmt.Errorf("failed to process env var: %w", err)
	}
	return cfg, nil
}
