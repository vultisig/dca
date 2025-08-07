package tx_indexer

import (
	"fmt"

	"github.com/kelseyhightower/envconfig"
	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/config"
)

func newConfig() (config.Config, error) {
	var cfg config.Config
	err := envconfig.Process("", &cfg)
	if err != nil {
		return config.Config{}, fmt.Errorf("failed to process env var: %w", err)
	}
	return cfg, nil
}
