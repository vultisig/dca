package btc

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type SendService struct{}

func NewSendService() *SendService {
	return &SendService{}
}

// BuildTransfer builds outputs for multiple recipients.
// toAddresses and amounts must have the same length.
// Returns the outputs slice and the change output index (always the last output).
func (s *SendService) BuildTransfer(
	toAddresses []string,
	amounts []uint64,
	fromAddress btcutil.Address,
) ([]*wire.TxOut, int, error) {
	if len(toAddresses) == 0 {
		return nil, 0, fmt.Errorf("toAddresses list is empty")
	}
	if len(toAddresses) != len(amounts) {
		return nil, 0, fmt.Errorf("toAddresses and amounts must have same length: got %d addresses and %d amounts", len(toAddresses), len(amounts))
	}

	var outputs []*wire.TxOut

	// Add recipient outputs
	for i, addr := range toAddresses {
		toAddr, err := btcutil.DecodeAddress(addr, nil)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to decode recipient[%d] address: %w", i, err)
		}

		toScript, err := txscript.PayToAddrScript(toAddr)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to create recipient[%d] script: %w", i, err)
		}

		outputs = append(outputs, &wire.TxOut{
			Value:    int64(amounts[i]),
			PkScript: toScript,
		})
	}

	// Add change output (last)
	changeScript, err := txscript.PayToAddrScript(fromAddress)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create change script: %w", err)
	}

	outputs = append(outputs, &wire.TxOut{
		Value:    0, // SDK calculates the change amount
		PkScript: changeScript,
	})

	changeOutputIndex := len(outputs) - 1

	return outputs, changeOutputIndex, nil
}
