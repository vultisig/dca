package thorchain

import (
	"context"
	"fmt"
	"strconv"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	utxo_swap "github.com/vultisig/dca/internal/utxo"
	"github.com/vultisig/vultisig-go/common"
)

// DogeMainNetParams defines the network parameters for the Dogecoin main network.
// This matches the definition in vultisig-go/address/dogecoin.go
var DogeMainNetParams = chaincfg.Params{
	Name: "mainnet",
	Net:  0xc0c0c0c0, // Dogecoin mainnet magic bytes

	// Address encoding magics
	PubKeyHashAddrID: 0x1E, // starts with D
	ScriptHashAddrID: 0x16, // starts with 9 or A
}

// ProviderDoge implements FeeProvider and SwapProvider for Dogecoin via THORChain.
type ProviderDoge struct {
	client *Client
}

// NewProviderDoge creates a new Dogecoin provider for THORChain swaps.
func NewProviderDoge(client *Client) *ProviderDoge {
	return &ProviderDoge{
		client: client,
	}
}

func (p *ProviderDoge) validateDoge(from utxo_swap.From, to utxo_swap.To) error {
	if to.Chain == common.Dogecoin {
		return fmt.Errorf("[DOGE] can't swap DOGE to DOGE")
	}

	_, err := parseThorNetwork(to.Chain)
	if err != nil {
		return fmt.Errorf("[DOGE] unsupported 'to' chain: %w", err)
	}

	return nil
}

// SatsPerByte returns the current fee rate for Dogecoin from THORChain.
func (p *ProviderDoge) SatsPerByte(ctx context.Context) (uint64, error) {
	info, err := p.client.getInboundAddresses(ctx, inboundAddressesRequest{})
	if err != nil {
		return 0, fmt.Errorf("[DOGE] failed to get inbound addresses: %w", err)
	}

	for _, addr := range info {
		if addr.Chain == doge {
			satsPerByte, er := strconv.ParseUint(addr.GasRate, 10, 64)
			if er != nil {
				return 0, fmt.Errorf("[DOGE] failed to parse gas rate: %w", er)
			}
			return satsPerByte, nil
		}
	}
	return 0, fmt.Errorf("[DOGE] no gas info found for Dogecoin")
}

// ChangeOutputIndex returns the index of the change output in swap transactions.
func (p *ProviderDoge) ChangeOutputIndex() int {
	return 1
}

// MakeOutputs builds the transaction outputs for a Dogecoin to X swap via THORChain.
func (p *ProviderDoge) MakeOutputs(
	ctx context.Context,
	from utxo_swap.From,
	to utxo_swap.To,
) (uint64, []*wire.TxOut, error) {
	if err := p.validateDoge(from, to); err != nil {
		return 0, nil, fmt.Errorf("[DOGE] invalid swap: %w", err)
	}

	toAsset, err := makeThorAsset(ctx, p.client, to.Chain, to.AssetID)
	if err != nil {
		return 0, nil, fmt.Errorf("[DOGE] failed to convert thor asset: %w", err)
	}

	quote, err := p.client.getQuote(ctx, quoteSwapRequest{
		FromAsset:         string(doge) + "." + string(doge),
		ToAsset:           toAsset,
		Amount:            fmt.Sprintf("%d", from.Amount),
		Destination:       to.Address,
		StreamingInterval: defaultStreamingInterval,
		StreamingQuantity: defaultStreamingQuantity,
	})
	if err != nil {
		return 0, nil, fmt.Errorf("[DOGE] failed to get quote: %w", err)
	}

	// Decode the THORChain inbound address using Dogecoin network params
	inboundAddr, err := btcutil.DecodeAddress(quote.InboundAddress, &DogeMainNetParams)
	if err != nil {
		return 0, nil, fmt.Errorf("[DOGE] failed to decode inbound address: %w", err)
	}

	inboundScript, err := txscript.PayToAddrScript(inboundAddr)
	if err != nil {
		return 0, nil, fmt.Errorf("[DOGE] failed to create inbound script: %w", err)
	}

	changeScript, err := from.Address.PayToAddrScript()
	if err != nil {
		return 0, nil, fmt.Errorf("[DOGE] failed to create change script: %w", err)
	}

	memoScript, err := createMemoScript(quote.Memo)
	if err != nil {
		return 0, nil, fmt.Errorf("[DOGE] failed to create memo script: %w", err)
	}

	expectedOut, err := strconv.ParseUint(quote.ExpectedAmountOut, 10, 64)
	if err != nil {
		return 0, nil, fmt.Errorf("[DOGE] failed to parse expected amount out: %w", err)
	}

	dustThreshold, err := strconv.ParseUint(quote.DustThreshold, 10, 64)
	if err != nil {
		return 0, nil, fmt.Errorf("[DOGE] failed to parse dust threshold: %w", err)
	}

	if from.Amount < dustThreshold {
		return 0, nil, fmt.Errorf("[DOGE] amount %d below dust threshold %d", from.Amount, dustThreshold)
	}

	outputs := []*wire.TxOut{{
		Value:    int64(from.Amount),
		PkScript: inboundScript,
	}, {
		Value:    0,
		PkScript: changeScript,
	}, {
		Value:    0,
		PkScript: memoScript,
	}}

	return expectedOut, outputs, nil
}

