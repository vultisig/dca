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

func (s *SendService) BuildTransfer(
	toAddress string,
	fromAddress btcutil.Address,
	amount uint64,
) ([]*wire.TxOut, int, error) {
	toAddr, err := btcutil.DecodeAddress(toAddress, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to decode to address: %w", err)
	}

	toScript, err := txscript.PayToAddrScript(toAddr)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create to script: %w", err)
	}

	changeScript, err := txscript.PayToAddrScript(fromAddress)
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
