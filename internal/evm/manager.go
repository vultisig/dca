package evm

import (
	"fmt"

	"github.com/vultisig/dca/internal/status"
	"github.com/vultisig/vultisig-go/common"
)

type Network struct {
	Approve *approveService
	Swap    *swapService
	Send    *sendService
	Signer  *signerService
	Status  *status.Status
}

type Manager struct {
	network map[common.Chain]*Network
}

func NewManager(network map[common.Chain]*Network) *Manager {
	return &Manager{
		network: network,
	}
}

func (m *Manager) Get(chain common.Chain) (*Network, error) {
	net, ok := m.network[chain]
	if !ok {
		return nil, fmt.Errorf("failed to get network for chain: %s", chain)
	}
	return net, nil
}
