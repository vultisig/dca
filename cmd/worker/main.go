package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"

	"github.com/ethereum/go-ethereum/ethclient"
	solanarpc "github.com/gagliardetto/solana-go/rpc"
	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/dca/internal/blockchair"
	"github.com/vultisig/dca/internal/btc"
	"github.com/vultisig/dca/internal/dca"
	"github.com/vultisig/dca/internal/evm"
	"github.com/vultisig/dca/internal/health"
	"github.com/vultisig/dca/internal/jupiter"
	"github.com/vultisig/dca/internal/oneinch"
	"github.com/vultisig/dca/internal/solana"
	"github.com/vultisig/dca/internal/thorchain"
	"github.com/vultisig/dca/internal/xrp"
	btcsdk "github.com/vultisig/recipes/sdk/btc"
	evmsdk "github.com/vultisig/recipes/sdk/evm"
	xrplsdk "github.com/vultisig/recipes/sdk/xrpl"
	"github.com/vultisig/verifier/plugin"
	plugin_config "github.com/vultisig/verifier/plugin/config"
	"github.com/vultisig/verifier/plugin/keysign"
	"github.com/vultisig/verifier/plugin/policy"
	"github.com/vultisig/verifier/plugin/policy/policy_pg"
	"github.com/vultisig/verifier/plugin/scheduler/scheduler_pg"
	"github.com/vultisig/verifier/plugin/tasks"
	"github.com/vultisig/verifier/plugin/tx_indexer"
	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/storage"
	"github.com/vultisig/verifier/vault"
	"github.com/vultisig/verifier/vault_config"
	"github.com/vultisig/vultisig-go/common"
	"github.com/vultisig/vultisig-go/relay"
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

	vaultStorage, err := vault.NewBlockStorageImp(cfg.BlockStorage)
	if err != nil {
		logger.Fatalf("failed to initialize vault storage: %v", err)
	}

	redisOptions := asynq.RedisClientOpt{
		Addr:     net.JoinHostPort(cfg.Redis.Host, cfg.Redis.Port),
		Username: cfg.Redis.User,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	}

	redisTLS := os.Getenv("REDIS_TLS")
	if redisTLS == "true" {
		redisOptions.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
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

	supportedChains, err := tx_indexer.Chains()
	if err != nil {
		logger.Fatalf("failed to get supported chains: %v", err)
	}

	txIndexerService := tx_indexer.NewService(
		logger,
		txStorage,
		supportedChains,
	)

	vaultService, err := vault.NewManagementService(
		cfg.VaultService,
		client,
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

	signer := keysign.NewSigner(
		logger,
		relay.NewRelayClient(cfg.VaultService.Relay.Server),
		[]keysign.Emitter{
			keysign.NewPluginEmitter(client, tasks.TypeKeySignDKLS, tasks.QUEUE_NAME),
			keysign.NewVerifierEmitter(cfg.Verifier.URL, cfg.Verifier.Token),
		},
		[]string{
			cfg.VaultService.LocalPartyPrefix,
			cfg.Verifier.PartyPrefix,
		},
	)

	networks := make(map[common.Chain]*evm.Network)

	thorchainClient := thorchain.NewClient(cfg.ThorChain.URL)
	oneInchClient := oneinch.NewClient(cfg.OneInch.BaseURL)

	networkConfigs := []struct {
		chain  common.Chain
		rpcURL string
	}{
		{common.Ethereum, cfg.Rpc.Ethereum.URL},
		{common.Arbitrum, cfg.Rpc.Arbitrum.URL},
		{common.Avalanche, cfg.Rpc.Avalanche.URL},
		{common.BscChain, cfg.Rpc.BSC.URL},
		{common.Base, cfg.Rpc.Base.URL},
		{common.Blast, cfg.Rpc.Blast.URL},
		{common.Optimism, cfg.Rpc.Optimism.URL},
		{common.Polygon, cfg.Rpc.Polygon.URL},
	}

	for _, c := range networkConfigs {
		evmID, er := c.chain.EvmID()
		if er != nil {
			logger.Fatalf("failed to initialize evm sdk: %s %v", c.chain.String(), er)
		}

		evmRpc, er := ethclient.DialContext(ctx, c.rpcURL)
		if er != nil {
			logger.Fatalf("failed to create rpc client: %s %v", c.chain.String(), er)
		}

		evmSdk := evmsdk.NewSDK(evmID, evmRpc, evmRpc.Client())
		network, er := evm.NewNetwork(
			ctx,
			c.chain,
			c.rpcURL,
			[]evm.Provider{
				oneinch.NewProvider(oneInchClient, evmRpc, evmSdk),
				thorchain.NewProviderEvm(thorchainClient, evmRpc, evmSdk),
			},
			signer,
			txIndexerService,
		)
		if er != nil {
			logger.Fatalf("failed to initialize %s network: %v", c.chain.String(), er)
		}
		networks[c.chain] = network
	}

	thorchainBtc := thorchain.NewProviderBtc(thorchainClient)
	blockchairClient := blockchair.NewClient(cfg.BTC.BlockchairURL)

	// Initialize XRP network
	xrpClient := xrp.NewClient(cfg.Rpc.XRP.URL)
	thorchainXrp := thorchain.NewProviderXrp(thorchainClient, xrpClient)

	// Initialize XRP SDK for signing and broadcasting
	xrpRpcClient := xrplsdk.NewHTTPRPCClient([]string{cfg.Rpc.XRP.URL})
	xrpSDK := xrplsdk.NewSDK(xrpRpcClient)

	xrpNetwork := xrp.NewNetwork(
		xrp.NewSwapService([]xrp.SwapProvider{thorchainXrp}),
		xrp.NewSendService(xrpClient),
		xrp.NewSignerService(xrpSDK, signer, txIndexerService),
		xrpClient,
	)

	jup, err := jupiter.NewProvider(cfg.Solana.JupiterAPIURL, solanarpc.New(cfg.Rpc.Solana.URL))
	if err != nil {
		logger.Fatalf("failed to initialize Jupiter provider: %v", err)
	}

	solanaNetwork, err := solana.NewNetwork(
		ctx,
		cfg.Rpc.Solana.URL,
		[]solana.Provider{
			jup,
		},
		signer,
		txIndexerService,
	)
	if err != nil {
		logger.Fatalf("failed to initialize Solana network: %v", err)
	}

	dcaConsumer := dca.NewConsumer(
		logger,
		policyService,
		evm.NewManager(networks),
		btc.NewNetwork(
			thorchainBtc,
			btc.NewSwapService([]btc.SwapProvider{thorchainBtc}),
			btc.NewSendService(),
			btc.NewSignerService(btcsdk.NewSDK(blockchairClient), signer, txIndexerService),
			blockchairClient,
		),
		solanaNetwork,
		xrpNetwork,
		vaultStorage,
		cfg.VaultService.EncryptionSecret,
	)

	healthServer := health.New(cfg.HealthPort)
	go func() {
		er := healthServer.Start(ctx, logger)
		if er != nil {
			logger.Errorf("health server failed: %v", er)
		}
	}()

	mux := asynq.NewServeMux()
	mux.HandleFunc(tasks.TypePluginTransaction, dcaConsumer.Handle)
	mux.HandleFunc(tasks.TypeKeySignDKLS, vaultService.HandleKeySignDKLS)
	mux.HandleFunc(tasks.TypeReshareDKLS, vaultService.HandleReshareDKLS)
	err = consumer.Run(mux)
	if err != nil {
		logger.Fatalf("failed to run consumer: %v", err)
	}
}

type config struct {
	VaultService vault_config.Config
	BlockStorage vault_config.BlockStorage
	Postgres     plugin_config.Database
	Redis        plugin_config.Redis
	Verifier     plugin_config.Verifier
	Rpc          rpc
	OneInch      oneInchConfig
	ThorChain    thorChainConfig
	BTC          btcConfig
	XRP          xrpConfig
	Solana       solanaConfig
	HealthPort   int
}

type oneInchConfig struct {
	BaseURL string
}

type thorChainConfig struct {
	URL string
}

type rpc struct {
	Ethereum  rpcItem
	Arbitrum  rpcItem
	Avalanche rpcItem
	BSC       rpcItem
	Base      rpcItem
	Blast     rpcItem
	Optimism  rpcItem
	Polygon   rpcItem
	XRP       rpcItem
	Solana    rpcItem
}

type rpcItem struct {
	URL string
}

type btcConfig struct {
	BlockchairURL string
}

type xrpConfig struct {
	RPC string
}

type solanaConfig struct {
	JupiterAPIURL string
}

func newConfig() (config, error) {
	var cfg config
	err := envconfig.Process("", &cfg)
	if err != nil {
		return config{}, fmt.Errorf("failed to process env var: %w", err)
	}
	return cfg, nil
}
