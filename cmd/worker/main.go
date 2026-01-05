package main

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/ethclient"
	solanarpc "github.com/gagliardetto/solana-go/rpc"
	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"

	"github.com/vultisig/dca/internal/blockchair"
	"github.com/vultisig/dca/internal/btc"
	"github.com/vultisig/dca/internal/evm"
	"github.com/vultisig/dca/internal/health"
	"github.com/vultisig/dca/internal/jupiter"
	"github.com/vultisig/dca/internal/logging"
	"github.com/vultisig/dca/internal/mayachain"
	"github.com/vultisig/dca/internal/metrics"
	"github.com/vultisig/dca/internal/oneinch"
	"github.com/vultisig/dca/internal/recurring"
	"github.com/vultisig/dca/internal/solana"
	"github.com/vultisig/dca/internal/thorchain"
	"github.com/vultisig/dca/internal/utxo"
	"github.com/vultisig/dca/internal/xrp"
	"github.com/vultisig/dca/internal/zcash"
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

	cfg, err := newConfig()
	if err != nil {
		logrus.Fatalf("failed to load config: %v", err)
	}

	logger := logging.NewLogger(cfg.LogFormat)

	// Start metrics server for worker
	metricsServer := metrics.StartMetricsServer(cfg.Metrics, []string{metrics.ServiceWorker}, logger)
	defer func() {
		if metricsServer != nil {
			if err := metricsServer.Stop(ctx); err != nil {
				logger.Errorf("failed to stop metrics server: %v", err)
			}
		}
	}()

	vaultStorage, err := vault.NewBlockStorageImp(cfg.BlockStorage)
	if err != nil {
		logger.Fatalf("failed to initialize vault storage: %v", err)
	}

	redisConnOpt, err := asynq.ParseRedisURI(cfg.Redis.URI)
	if err != nil {
		logger.Fatalf("failed to parse redis URI: %v", err)
	}

	client := asynq.NewClient(redisConnOpt)
	consumer := asynq.NewServer(
		redisConnOpt,
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
		nil,
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
		recurring.NewSchedulerService(schedulerStorage),
		logger,
	)
	if err != nil {
		logger.Fatalf("failed to initialize policy service: %v", err)
	}

	signerSend := keysign.NewSigner(
		logger,
		relay.NewRelayClient(cfg.VaultService.Relay.Server),
		[]keysign.Emitter{
			keysign.NewPluginEmitter(client, tasks.TypeKeySignDKLS, tasks.QUEUE_NAME),
			keysign.NewVerifierEmitter(cfg.Verifier.URL, cfg.Verifier.SendToken),
		},
		[]string{
			cfg.VaultService.LocalPartyPrefix,
			cfg.Verifier.PartyPrefix,
		},
	)
	signerSwap := keysign.NewSigner(
		logger,
		relay.NewRelayClient(cfg.VaultService.Relay.Server),
		[]keysign.Emitter{
			keysign.NewPluginEmitter(client, tasks.TypeKeySignDKLS, tasks.QUEUE_NAME),
			keysign.NewVerifierEmitter(cfg.Verifier.URL, cfg.Verifier.SwapToken),
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
			signerSend,
			signerSwap,
			txIndexerService,
		)
		if er != nil {
			logger.Fatalf("failed to initialize %s network: %v", c.chain.String(), er)
		}
		networks[c.chain] = network
	}

	thorchainBtc := thorchain.NewProviderBtc(thorchainClient)
	blockchairBtcClient := blockchair.NewClient(cfg.BTC.BlockchairURL)

	// Initialize Blockchair clients for other UTXO chains
	blockchairLtcClient := blockchair.NewClientForChain(cfg.LTC.BlockchairURL, "litecoin")
	blockchairDogeClient := blockchair.NewClientForChain(cfg.DOGE.BlockchairURL, "dogecoin")
	blockchairBchClient := blockchair.NewClientForChain(cfg.BCH.BlockchairURL, "bitcoin-cash")

	// Initialize XRP network
	xrpClient := xrp.NewClient(cfg.Rpc.XRP.URL)
	thorchainXrp := thorchain.NewProviderXrp(thorchainClient, xrpClient)

	// Initialize XRP SDK for signing and broadcasting
	xrpRpcClient := xrplsdk.NewHTTPRPCClient([]string{cfg.Rpc.XRP.URL})
	xrpSDK := xrplsdk.NewSDK(xrpRpcClient)

	xrpNetwork := xrp.NewNetwork(
		xrp.NewSwapService([]xrp.SwapProvider{thorchainXrp}),
		xrp.NewSendService(xrpClient),
		xrp.NewSignerService(xrpSDK, signerSend, txIndexerService),
		xrp.NewSignerService(xrpSDK, signerSwap, txIndexerService),
		xrpClient,
	)

	// Initialize MayaChain client for Zcash swaps
	mayachainClient := mayachain.NewClient(cfg.MayaChain.URL)
	mayachainZcash := mayachain.NewProviderZcash(mayachainClient)

	// Initialize Zcash network
	zcashClient := zcash.NewClient(cfg.ZEC.BlockchairURL)

	zcashNetwork := zcash.NewNetwork(
		mayachainZcash,
		zcash.NewSwapService([]zcash.SwapProvider{mayachainZcash}),
		zcash.NewSendService(),
		zcash.NewSignerService(zcashClient, signerSend, txIndexerService),
		zcash.NewSignerService(zcashClient, signerSwap, txIndexerService),
		zcashClient,
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
		signerSend,
		signerSwap,
		txIndexerService,
	)
	if err != nil {
		logger.Fatalf("failed to initialize Solana network: %v", err)
	}

	// Initialize chain-specific THORChain providers for UTXO chains
	thorchainLtc := thorchain.NewProviderLtc(thorchainClient)
	thorchainDoge := thorchain.NewProviderDoge(thorchainClient)
	thorchainBch := thorchain.NewProviderBch(thorchainClient)

	// Initialize LTC network with chain-specific provider
	ltcNetwork := utxo.NewNetwork(
		common.Litecoin,
		thorchainLtc,
		utxo.NewSwapService([]utxo.SwapProvider{thorchainLtc}),
		utxo.NewSendService(),
		utxo.NewSignerService(common.Litecoin, btcsdk.NewSDK(blockchairLtcClient), signerSend, txIndexerService),
		utxo.NewSignerService(common.Litecoin, btcsdk.NewSDK(blockchairLtcClient), signerSwap, txIndexerService),
		blockchairLtcClient,
	)

	// Initialize DOGE network with chain-specific provider
	dogeNetwork := utxo.NewNetwork(
		common.Dogecoin,
		thorchainDoge,
		utxo.NewSwapService([]utxo.SwapProvider{thorchainDoge}),
		utxo.NewSendService(),
		utxo.NewSignerService(common.Dogecoin, btcsdk.NewSDK(blockchairDogeClient), signerSend, txIndexerService),
		utxo.NewSignerService(common.Dogecoin, btcsdk.NewSDK(blockchairDogeClient), signerSwap, txIndexerService),
		blockchairDogeClient,
	)

	// Initialize BCH network with chain-specific provider
	bchNetwork := utxo.NewNetwork(
		common.BitcoinCash,
		thorchainBch,
		utxo.NewSwapService([]utxo.SwapProvider{thorchainBch}),
		utxo.NewSendService(),
		utxo.NewSignerService(common.BitcoinCash, btcsdk.NewSDK(blockchairBchClient), signerSend, txIndexerService),
		utxo.NewSignerService(common.BitcoinCash, btcsdk.NewSDK(blockchairBchClient), signerSwap, txIndexerService),
		blockchairBchClient,
	)

	recurringConsumer := recurring.NewConsumer(
		logger,
		policyService,
		evm.NewManager(networks),
		btc.NewNetwork(
			thorchainBtc,
			btc.NewSwapService([]btc.SwapProvider{thorchainBtc}),
			btc.NewSendService(),
			btc.NewSignerService(btcsdk.NewSDK(blockchairBtcClient), signerSend, txIndexerService),
			btc.NewSignerService(btcsdk.NewSDK(blockchairBtcClient), signerSwap, txIndexerService),
			blockchairBtcClient,
		),
		ltcNetwork,
		dogeNetwork,
		bchNetwork,
		solanaNetwork,
		xrpNetwork,
		zcashNetwork,
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
	mux.HandleFunc(tasks.TypePluginTransaction, recurringConsumer.Handle)
	mux.HandleFunc(tasks.TypeKeySignDKLS, vaultService.HandleKeySignDKLS)
	mux.HandleFunc(tasks.TypeReshareDKLS, vaultService.HandleReshareDKLS)
	err = consumer.Run(mux)
	if err != nil {
		logger.Fatalf("failed to run consumer: %v", err)
	}
}

type config struct {
	LogFormat    logging.LogFormat
	VaultService vault_config.Config
	BlockStorage vault_config.BlockStorage
	Postgres     plugin_config.Database
	Redis        plugin_config.Redis
	Verifier     verifier
	Rpc          rpc
	OneInch      oneInchConfig
	ThorChain    thorChainConfig
	MayaChain    mayaChainConfig
	BTC          btcConfig
	LTC          ltcConfig
	DOGE         dogeConfig
	BCH          bchConfig
	XRP          xrpConfig
	ZEC          zecConfig
	Solana       solanaConfig
	HealthPort   int
	Metrics      metrics.Config
}

type oneInchConfig struct {
	BaseURL string
}

type thorChainConfig struct {
	URL string
}

type mayaChainConfig struct {
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

type ltcConfig struct {
	BlockchairURL string
}

type dogeConfig struct {
	BlockchairURL string
}

type bchConfig struct {
	BlockchairURL string
}

type xrpConfig struct {
	RPC string
}

type zecConfig struct {
	BlockchairURL string
}

type solanaConfig struct {
	JupiterAPIURL string
}

type verifier struct {
	URL         string `mapstructure:"url"`
	SendToken   string `mapstructure:"send_token"`
	SwapToken   string `mapstructure:"swap_token"`
	PartyPrefix string `mapstructure:"party_prefix"`
}

func newConfig() (config, error) {
	var cfg config
	err := envconfig.Process("", &cfg)
	if err != nil {
		return config{}, fmt.Errorf("failed to process env var: %w", err)
	}
	return cfg, nil
}
