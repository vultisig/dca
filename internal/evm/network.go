package evm

import (
	"fmt"

	"github.com/ethereum/go-ethereum/ethclient"
	rcommon "github.com/vultisig/recipes/common"
	"github.com/vultisig/recipes/sdk/evm"
)

type ProviderConstructor func(rcommon.Chain, *ethclient.Client, *evm.SDK) Provider

func NewNetwork(chain rcommon.Chain, rpcUrl string, providers []ProviderConstructor) (*Network, error) {
	evmID, err := chain.EvmID()
	if err != nil {
		return nil, fmt.Errorf("failed to get EVM ID: %w", err)
	}

	rpc, err := ethclient.Dial(rpcUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to RPC: %w", err)
	}

	sdk := evm.NewSDK(evmID, rpc, rpc.Client())

	var swaps []Provider
	for _, provider := range providers {
		swaps = append(swaps, provider(chain, rpc, sdk))
	}

	return &Network{
		Approve: newApproveService(rpc, sdk),
		Swap:    newSwapService(swaps),
	}, nil
}
