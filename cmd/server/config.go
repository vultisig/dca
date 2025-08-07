package main

import (
	"fmt"

	"github.com/kelseyhightower/envconfig"
	plugin_config "github.com/vultisig/verifier/plugin/config"
	"github.com/vultisig/verifier/plugin/server"
	"github.com/vultisig/verifier/vault_config"
)

type config struct {
	Server       server.Config
	BlockStorage vault_config.BlockStorage
	Postgres     plugin_config.Database
	Redis        plugin_config.Redis
	DataDog      dataDog
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
