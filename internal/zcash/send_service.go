package zcash

import (
	"fmt"
	"math"
)

type SendService struct{}

func NewSendService() *SendService {
	return &SendService{}
}

func (s *SendService) BuildTransfer(
	toAddress string,
	fromAddress string,
	amount uint64,
) ([]*TxOutput, int, error) {
	if amount > uint64(math.MaxInt64) {
		return nil, 0, fmt.Errorf("amount %d exceeds maximum int64 value", amount)
	}

	toScript, err := PayToAddrScript(toAddress)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create to script: %w", err)
	}

	changeScript, err := PayToAddrScript(fromAddress)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create change script: %w", err)
	}

	outputs := []*TxOutput{
		{
			Value:   int64(amount),
			Script:  toScript,
			Address: toAddress,
		},
		{
			Value:   0, // Change amount will be calculated later
			Script:  changeScript,
			Address: fromAddress,
		},
	}

	changeOutputIndex := 1

	return outputs, changeOutputIndex, nil
}
