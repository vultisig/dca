package main

import (
	"fmt"

	"github.com/kelseyhightower/envconfig"
	plugin_config "github.com/vultisig/verifier/plugin/config"
)

type config struct {
	Postgres plugin_config.Database
	Redis    plugin_config.Redis
}

func newConfig() (config, error) {
	var cfg config
	err := envconfig.Process("", &cfg)
	if err != nil {
		return config{}, fmt.Errorf("failed to process env var: %w", err)
	}
	return cfg, nil
}
