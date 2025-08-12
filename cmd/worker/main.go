package main

import (
	"context"

	"github.com/DataDog/datadog-go/statsd"
	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/dca/internal/dca"
	"github.com/vultisig/dca/internal/evm"
	"github.com/vultisig/dca/internal/uniswap"
	"github.com/vultisig/recipes/common"
	"github.com/vultisig/verifier/plugin"
	"github.com/vultisig/verifier/plugin/keysign"
	"github.com/vultisig/verifier/plugin/policy"
	"github.com/vultisig/verifier/plugin/policy/policy_pg"
	"github.com/vultisig/verifier/plugin/scheduler/scheduler_pg"
	"github.com/vultisig/verifier/plugin/tasks"
	"github.com/vultisig/verifier/plugin/tx_indexer"
	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/storage"
	"github.com/vultisig/verifier/vault"
	"github.com/vultisig/vultiserver/relay"
)

func main() {
	ctx := context.Background()

	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	cfg, err := newConfig()
	if err != nil {
		logger.Fatalf("failed to load config: %v", err)
	}

	sdClient, err := statsd.New(cfg.DataDog.Host + ":" + cfg.DataDog.Port)
	if err != nil {
		logger.Fatalf("failed to initialize StatsD client: %v", err)
	}
	vaultStorage, err := vault.NewBlockStorageImp(cfg.BlockStorage)
	if err != nil {
		logger.Fatalf("failed to initialize vault storage: %v", err)
	}

	redisOptions := asynq.RedisClientOpt{
		Addr:     cfg.Redis.Host + ":" + cfg.Redis.Port,
		Username: cfg.Redis.User,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	}

	client := asynq.NewClient(redisOptions)
	consumer := asynq.NewServer(
		redisOptions,
		asynq.Config{
			Logger:      logger,
			Concurrency: 10,
			Queues: map[string]int{
				tasks.QUEUE_NAME: 10,
			},
		},
	)

	pgPool, err := pgxpool.New(ctx, cfg.Postgres.DSN)
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
		logger.Fatalf("failed to initialize Postgres pool: %v", err)
	}

	txIndexerService := tx_indexer.NewService(
		logger,
		txStorage,
		tx_indexer.Chains(),
	)

	vaultService, err := vault.NewManagementService(
		cfg.VaultServiceConfig,
		client,
		sdClient,
		vaultStorage,
		txIndexerService,
	)
	if err != nil {
		logger.Fatalf("failed to create vault service: %v", err)
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

	ethRpc, ethSdk, err := evm.NewNetwork(common.Ethereum, cfg.Rpc.Ethereum.URL)
	if err != nil {
		logger.Fatalf("failed to initialize Ethereum network: %v", err)
	}

	dcaConsumer := dca.NewConsumer(
		policyService,
		evm.NewManager(map[common.Chain]*evm.Network{
			common.Ethereum: {
				Approve: evm.NewApproveService(ethRpc, ethSdk),
				Swap: evm.NewSwapService([]evm.Provider{
					uniswap.NewProviderV2(
						common.Ethereum,
						ethRpc,
						ethSdk,
						ecommon.HexToAddress(cfg.Uniswap.RouterV2.Ethereum),
					),
				}),
			},
		}),
		keysign.NewSigner(
			logger,
			relay.NewRelayClient(cfg.VaultServiceConfig.Relay.Server),
			[]keysign.Emitter{
				keysign.NewPluginEmitter(client, tasks.TypeKeySignDKLS, tasks.QUEUE_NAME),
				keysign.NewVerifierEmitter(cfg.Verifier.URL, cfg.Verifier.Token),
			},
			[]string{
				cfg.VaultServiceConfig.LocalPartyPrefix,
				cfg.Verifier.PartyPrefix,
			},
		),
	)

	mux := asynq.NewServeMux()
	mux.HandleFunc(tasks.TypePluginTransaction, dcaConsumer.Handle)
	mux.HandleFunc(tasks.TypeKeySignDKLS, vaultService.HandleKeySignDKLS)
	mux.HandleFunc(tasks.TypeReshareDKLS, vaultService.HandleReshareDKLS)
	err = consumer.Run(mux)
	if err != nil {
		logger.Fatalf("failed to run consumer: %v", err)
	}
}
