package mayachain

import (
	"context"
	"fmt"
	"math"
	"strconv"

	"github.com/vultisig/app-recurring/internal/zcash"
	"github.com/vultisig/vultisig-go/common"
)

// ProviderZcash implements the Zcash swap provider for MayaChain
type ProviderZcash struct {
	client *Client
}

// NewProviderZcash creates a new Zcash provider for MayaChain swaps
func NewProviderZcash(client *Client) *ProviderZcash {
	return &ProviderZcash{
		client: client,
	}
}

func (p *ProviderZcash) validateZcash(from zcash.From, to zcash.To) error {
	if to.Chain == common.Zcash {
		return fmt.Errorf("can't swap ZEC to ZEC")
	}

	_, err := parseMayaNetwork(to.Chain)
	if err != nil {
		return fmt.Errorf("unsupported 'to' chain for MayaChain: %w", err)
	}

	// Validate from address is a valid Zcash transparent address
	if err := zcash.ValidateAddress(from.Address); err != nil {
		return fmt.Errorf("invalid 'from' address: %w", err)
	}

	return nil
}

// ZatoshisPerByte returns the current fee rate for Zcash transactions
func (p *ProviderZcash) ZatoshisPerByte(ctx context.Context) (uint64, error) {
	info, err := p.client.getInboundAddresses(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get inbound addresses: %w", err)
	}

	for _, addr := range info {
		if addr.Chain == zec {
			zatoshisPerByte, er := strconv.ParseUint(addr.GasRate, 10, 64)
			if er != nil {
				return 0, fmt.Errorf("failed to parse gas rate: %w", er)
			}
			return zatoshisPerByte, nil
		}
	}
	return 0, fmt.Errorf("no gas info found for ZEC")
}

// ChangeOutputIndex returns the index of the change output in swap transactions
func (p *ProviderZcash) ChangeOutputIndex() int {
	return 1
}

// MakeOutputs creates transaction outputs for a MayaChain swap
func (p *ProviderZcash) MakeOutputs(
	ctx context.Context,
	from zcash.From,
	to zcash.To,
) (uint64, []*zcash.TxOutput, error) {
	if err := p.validateZcash(from, to); err != nil {
		return 0, nil, fmt.Errorf("invalid swap: %w", err)
	}

	toAsset, err := MakeMayaAsset(ctx, p.client, to.Chain, to.AssetID)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to convert maya asset: %w", err)
	}

	quote, err := p.client.GetQuote(ctx, QuoteSwapRequest{
		FromAsset:         string(zec) + "." + string(zec),
		ToAsset:           toAsset,
		Amount:            fmt.Sprintf("%d", from.Amount),
		Destination:       to.Address,
		StreamingInterval: DefaultStreamingInterval,
		StreamingQuantity: DefaultStreamingQuantity,
	})
	if err != nil {
		return 0, nil, fmt.Errorf("failed to get quote: %w", err)
	}

	// Create script for MayaChain inbound address
	inboundScript, err := zcash.PayToAddrScript(quote.InboundAddress)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create inbound script: %w", err)
	}

	// Create script for change address
	changeScript, err := zcash.PayToAddrScript(from.Address)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create change script: %w", err)
	}

	// Create OP_RETURN script for memo
	memoScript, err := zcash.CreateMemoScript(quote.Memo)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create memo script: %w", err)
	}

	expectedOut, err := strconv.ParseUint(quote.ExpectedAmountOut, 10, 64)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to parse expected amount out: %w", err)
	}

	dustThreshold, err := strconv.ParseUint(quote.DustThreshold, 10, 64)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to parse dust threshold: %w", err)
	}

	if from.Amount < dustThreshold {
		return 0, nil, fmt.Errorf("amount %d below dust threshold %d", from.Amount, dustThreshold)
	}

	if from.Amount > uint64(math.MaxInt64) {
		return 0, nil, fmt.Errorf("amount %d exceeds maximum int64 value", from.Amount)
	}

	outputs := []*zcash.TxOutput{
		{
			Value:   int64(from.Amount),
			Script:  inboundScript,
			Address: quote.InboundAddress,
		},
		{
			Value:   0, // Change amount will be calculated later
			Script:  changeScript,
			Address: from.Address,
		},
		{
			Value:   0,
			Script:  memoScript,
			Address: "", // OP_RETURN has no address
		},
	}

	return expectedOut, outputs, nil
}
