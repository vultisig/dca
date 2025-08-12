package evm

import (
	"fmt"

	"github.com/ethereum/go-ethereum/ethclient"
	rcommon "github.com/vultisig/recipes/common"
	"github.com/vultisig/recipes/sdk/evm"
)

func NewNetwork(chain rcommon.Chain, rpcUrl string) (*ethclient.Client, *evm.SDK, error) {
	evmID, err := chain.EvmID()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get EVM ID: %w", err)
	}

	rpc, err := ethclient.Dial(rpcUrl)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to RPC: %w", err)
	}

	sdk := evm.NewSDK(evmID, rpc, rpc.Client())

	return rpc, sdk, nil
}
