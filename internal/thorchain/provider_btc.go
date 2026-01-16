package thorchain

import (
	"context"
	"fmt"
	"strconv"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	btc_swap "github.com/vultisig/app-recurring/internal/btc"
	"github.com/vultisig/app-recurring/internal/utxo/address"
	"github.com/vultisig/vultisig-go/common"
)

type ProviderBtc struct {
	client *Client
}

func NewProviderBtc(client *Client) *ProviderBtc {
	return &ProviderBtc{
		client: client,
	}
}

func (p *ProviderBtc) validateBtc(from btc_swap.From, to btc_swap.To) error {
	if to.Chain == common.Bitcoin {
		return fmt.Errorf("can't swap btc to btc")
	}

	_, err := parseThorNetwork(to.Chain)
	if err != nil {
		return fmt.Errorf("unsupported 'to' chain: %w", err)
	}

	// Validate from address is a BTCAddress with a supported native type
	btcAddr, ok := from.Address.(*address.BTCAddress)
	if !ok {
		return fmt.Errorf("unsupported 'from' address type: expected BTCAddress")
	}
	switch btcAddr.Native().(type) {
	case *btcutil.AddressWitnessScriptHash,
		*btcutil.AddressWitnessPubKeyHash,
		*btcutil.AddressPubKeyHash,
		*btcutil.AddressScriptHash,
		*btcutil.AddressTaproot:
	default:
		return fmt.Errorf("unsupported 'from' address type")
	}

	return nil
}

func (p *ProviderBtc) SatsPerByte(ctx context.Context) (uint64, error) {
	info, err := p.client.getInboundAddresses(ctx, inboundAddressesRequest{})
	if err != nil {
		return 0, fmt.Errorf("failed to get inbound addresses: %w", err)
	}

	for _, addr := range info {
		if addr.Chain == btc {
			satsPerByte, er := strconv.ParseUint(addr.GasRate, 10, 64)
			if er != nil {
				return 0, fmt.Errorf("failed to parse gas rate: %w", er)
			}
			return satsPerByte, nil
		}
	}
	return 0, fmt.Errorf("no gas info found")
}

func (p *ProviderBtc) ChangeOutputIndex() int {
	return 1
}

func (p *ProviderBtc) MakeOutputs(
	ctx context.Context,
	from btc_swap.From,
	to btc_swap.To,
) (uint64, []*wire.TxOut, error) {
	if err := p.validateBtc(from, to); err != nil {
		return 0, nil, fmt.Errorf("invalid swap: %w", err)
	}

	toAsset, err := makeThorAsset(ctx, p.client, to.Chain, to.AssetID)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to convert thor asset: %w", err)
	}

	quote, err := p.client.getQuote(ctx, quoteSwapRequest{
		FromAsset:         string(btc) + "." + string(btc),
		ToAsset:           toAsset,
		Amount:            fmt.Sprintf("%d", from.Amount),
		Destination:       to.Address,
		StreamingInterval: defaultStreamingInterval,
		StreamingQuantity: defaultStreamingQuantity,
		//ToleranceBps:      defaultToleranceBps,
	})
	if err != nil {
		return 0, nil, fmt.Errorf("failed to get quote: %w", err)
	}

	inboundAddr, err := btcutil.DecodeAddress(quote.InboundAddress, &chaincfg.MainNetParams)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to decode inbound address: %w", err)
	}

	inboundScript, err := payToAddrScript(inboundAddr)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create inbound script: %w", err)
	}

	changeScript, err := from.Address.PayToAddrScript()
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create change script: %w", err)
	}

	memoScript, err := createMemoScript(quote.Memo)
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

func payToAddrScript(addr btcutil.Address) ([]byte, error) {
	return txscript.PayToAddrScript(addr)
}

func createMemoScript(memo string) ([]byte, error) {
	// max 80 chars validation inside txscript.NullDataScript,
	// compound memos >80 chars not supported yet,
	// it only required for Cosmos long addresses
	return txscript.NullDataScript([]byte(memo))
}
