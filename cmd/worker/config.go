package main

import (
	"fmt"

	"github.com/kelseyhightower/envconfig"
	plugin_config "github.com/vultisig/verifier/plugin/config"
	"github.com/vultisig/verifier/vault_config"
)

type config struct {
	VaultServiceConfig vault_config.Config
	BlockStorage       vault_config.BlockStorage
	Postgres           plugin_config.Database
	Redis              plugin_config.Redis
	Verifier           plugin_config.Verifier
	Rpc                rpc
	Uniswap            uniswapConfig
	DataDog            dataDog
}

type uniswapConfig struct {
	RouterV2 router
}

type router struct {
	Ethereum string
}

type rpc struct {
	Ethereum rpcItem
}

type rpcItem struct {
	URL string
}

type dataDog struct {
	Host string
	Port string
}

func newConfig() (config, error) {
	var cfg config
	err := envconfig.Process("", &cfg)
	if err != nil {
		return config{}, fmt.Errorf("failed to process env var: %w", err)
	}
	return cfg, nil
}
