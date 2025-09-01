package thorchain

import (
	"context"
	"fmt"
	"strconv"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/ethereum/go-ethereum/params"
	btc_swap "github.com/vultisig/dca/internal/btc"
	"github.com/vultisig/vultisig-go/common"
)

type Provider struct {
	client *Client
}

func NewProvider(client *Client) *Provider {
	return &Provider{
		client: client,
	}
}

func (p *Provider) validateBtc(from btc_swap.From, to btc_swap.To) error {
	_, err := toThor(to.Chain)
	if err != nil {
		return fmt.Errorf("unsupported 'to' chain: %w", err)
	}

	switch from.Address.(type) {
	case btcutil.AddressWitnessScriptHash,
		btcutil.AddressWitnessPubKeyHash,
		btcutil.AddressPubKeyHash,
		btcutil.AddressScriptHash,
		btcutil.AddressTaproot:
	default:
		return fmt.Errorf("unsupported 'from' address type")
	}

	return nil
}

func (p *Provider) SatsPerByte(ctx context.Context) (uint64, error) {
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

func (p *Provider) MakeOutputs(
	ctx context.Context,
	from btc_swap.From,
	to btc_swap.To,
) (uint64, []*wire.TxOut, error) {
	p.validateBtc(from, to)
}
