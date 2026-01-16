package utxo

import (
	"fmt"

	"github.com/btcsuite/btcd/wire"
	"github.com/vultisig/app-recurring/internal/utxo/address"
)

// SendService handles building send transactions for UTXO chains.
type SendService struct{}

// NewSendService creates a new SendService.
func NewSendService() *SendService {
	return &SendService{}
}

// BuildTransfer builds transaction outputs for a transfer.
// Returns the outputs and the index of the change output.
func (s *SendService) BuildTransfer(
	toAddress address.UTXOAddress,
	fromAddress address.UTXOAddress,
	amount uint64,
) ([]*wire.TxOut, int, error) {
	toScript, err := toAddress.PayToAddrScript()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create to script: %w", err)
	}

	changeScript, err := fromAddress.PayToAddrScript()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create change script: %w", err)
	}

	outputs := []*wire.TxOut{
		{
			Value:    int64(amount),
			PkScript: toScript,
		},
		{
			Value:    0,
			PkScript: changeScript,
		},
	}

	changeOutputIndex := 1

	return outputs, changeOutputIndex, nil
}

