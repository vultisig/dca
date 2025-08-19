package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"

	"github.com/vultisig/recipes/types"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	host       = flag.String("host", "http://localhost:8082", "dca server host")
	flatPreset = flag.String("preset", "", "preset to execute")
)

var presets = map[string]func(context.Context) error{
	"policyEth": policyEth,
}

func main() {
	flag.Parse()

	if *flatPreset == "" {
		panic("preset is required")
	}

	ctx := context.Background()
	err := presets[*flatPreset](ctx)
	if err != nil {
		panic(err)
	}
}

func suggest(cfg map[string]any) (*types.PolicySuggest, error) {
	reqBody, err := json.Marshal(map[string]map[string]any{
		"configuration": cfg,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	res, err := http.DefaultClient.Post(
		*host+"/plugin/recipe-specification/suggest",
		"application/json",
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to make http call: %w", err)
	}
	defer func() {
		_ = res.Body.Close()
	}()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	r := &types.PolicySuggest{}
	err = protojson.Unmarshal(body, r)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return r, nil
}

func policyEth(ctx context.Context) error {
	pp, err := suggest(map[string]any{
		"frequency":  "hourly",
		"fromChain":  "Ethereum",
		"fromAsset":  "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
		"fromAmount": "1000000",
		"toChain":    "Ethereum",
		"toAsset":    "0xdac17f958d2ee523a2206206994597c13d831ec7",
		"toAddress":  "0xcB9B049B9c937acFDB87EeCfAa9e7f2c51E754f5",
	})
	if err != nil {
		return fmt.Errorf("failed to suggest: %w", err)
	}
	fmt.Printf("%+v\n", pp)
	return nil
}
