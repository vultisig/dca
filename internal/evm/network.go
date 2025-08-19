package evm

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/vultisig/dca/internal/status"
	"github.com/vultisig/recipes/sdk/evm"
	"github.com/vultisig/verifier/plugin/keysign"
	"github.com/vultisig/verifier/plugin/tx_indexer"
	txrpc "github.com/vultisig/verifier/plugin/tx_indexer/pkg/rpc"
	rcommon "github.com/vultisig/vultisig-go/common"
)

type ProviderConstructor func(rcommon.Chain, *ethclient.Client, *evm.SDK) Provider

func NewNetwork(
	ctx context.Context,
	chain rcommon.Chain,
	rpcUrl string,
	providers []ProviderConstructor,
	signer *keysign.Signer,
	txIndexer *tx_indexer.Service,
) (*Network, error) {
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

	rpcCaller, err := txrpc.NewEvm(ctx, rpcUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to RPC: %w", err)
	}

	return &Network{
		Approve: newApproveService(rpc, sdk),
		Swap:    newSwapService(swaps),
		Signer:  newSignerService(sdk, chain, signer, txIndexer),
		Status:  status.NewStatus(rpcCaller),
	}, nil
}
