package thorchain

import (
	"context"
	"fmt"
	"strconv"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	bchchaincfg "github.com/gcash/bchd/chaincfg"
	"github.com/gcash/bchutil"

	utxo_swap "github.com/vultisig/dca/internal/utxo"
	"github.com/vultisig/vultisig-go/common"
)

// ProviderBch implements FeeProvider and SwapProvider for Bitcoin Cash via THORChain.
type ProviderBch struct {
	client *Client
}

// NewProviderBch creates a new Bitcoin Cash provider for THORChain swaps.
func NewProviderBch(client *Client) *ProviderBch {
	return &ProviderBch{
		client: client,
	}
}

func (p *ProviderBch) validateBch(from utxo_swap.From, to utxo_swap.To) error {
	if to.Chain == common.BitcoinCash {
		return fmt.Errorf("[BCH] can't swap BCH to BCH")
	}

	_, err := parseThorNetwork(to.Chain)
	if err != nil {
		return fmt.Errorf("[BCH] unsupported 'to' chain: %w", err)
	}

	return nil
}

// SatsPerByte returns the current fee rate for Bitcoin Cash from THORChain.
func (p *ProviderBch) SatsPerByte(ctx context.Context) (uint64, error) {
	info, err := p.client.getInboundAddresses(ctx, inboundAddressesRequest{})
	if err != nil {
		return 0, fmt.Errorf("[BCH] failed to get inbound addresses: %w", err)
	}

	for _, addr := range info {
		if addr.Chain == bch {
			satsPerByte, er := strconv.ParseUint(addr.GasRate, 10, 64)
			if er != nil {
				return 0, fmt.Errorf("[BCH] failed to parse gas rate: %w", er)
			}
			return satsPerByte, nil
		}
	}
	return 0, fmt.Errorf("[BCH] no gas info found for Bitcoin Cash")
}

// ChangeOutputIndex returns the index of the change output in swap transactions.
func (p *ProviderBch) ChangeOutputIndex() int {
	return 1
}

// MakeOutputs builds the transaction outputs for a Bitcoin Cash to X swap via THORChain.
func (p *ProviderBch) MakeOutputs(
	ctx context.Context,
	from utxo_swap.From,
	to utxo_swap.To,
) (uint64, []*wire.TxOut, error) {
	if err := p.validateBch(from, to); err != nil {
		return 0, nil, fmt.Errorf("[BCH] invalid swap: %w", err)
	}

	toAsset, err := makeThorAsset(ctx, p.client, to.Chain, to.AssetID)
	if err != nil {
		return 0, nil, fmt.Errorf("[BCH] failed to convert thor asset: %w", err)
	}

	quote, err := p.client.getQuote(ctx, quoteSwapRequest{
		FromAsset:         string(bch) + "." + string(bch),
		ToAsset:           toAsset,
		Amount:            fmt.Sprintf("%d", from.Amount),
		Destination:       to.Address,
		StreamingInterval: defaultStreamingInterval,
		StreamingQuantity: defaultStreamingQuantity,
	})
	if err != nil {
		return 0, nil, fmt.Errorf("[BCH] failed to get quote: %w", err)
	}

	// Decode the THORChain inbound address using Bitcoin Cash network params
	inboundAddr, err := bchutil.DecodeAddress(quote.InboundAddress, &bchchaincfg.MainNetParams)
	if err != nil {
		return 0, nil, fmt.Errorf("[BCH] failed to decode inbound address: %w", err)
	}

	inboundScript, err := bchPayToAddrScript(inboundAddr)
	if err != nil {
		return 0, nil, fmt.Errorf("[BCH] failed to create inbound script: %w", err)
	}

	changeScript, err := from.Address.PayToAddrScript()
	if err != nil {
		return 0, nil, fmt.Errorf("[BCH] failed to create change script: %w", err)
	}

	memoScript, err := createMemoScript(quote.Memo)
	if err != nil {
		return 0, nil, fmt.Errorf("[BCH] failed to create memo script: %w", err)
	}

	expectedOut, err := strconv.ParseUint(quote.ExpectedAmountOut, 10, 64)
	if err != nil {
		return 0, nil, fmt.Errorf("[BCH] failed to parse expected amount out: %w", err)
	}

	dustThreshold, err := strconv.ParseUint(quote.DustThreshold, 10, 64)
	if err != nil {
		return 0, nil, fmt.Errorf("[BCH] failed to parse dust threshold: %w", err)
	}

	if from.Amount < dustThreshold {
		return 0, nil, fmt.Errorf("[BCH] amount %d below dust threshold %d", from.Amount, dustThreshold)
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

// bchPayToAddrScript creates a pay-to-address script for Bitcoin Cash addresses.
func bchPayToAddrScript(addr bchutil.Address) ([]byte, error) {
	switch a := addr.(type) {
	case *bchutil.AddressPubKeyHash:
		// P2PKH: OP_DUP OP_HASH160 <pubkey-hash> OP_EQUALVERIFY OP_CHECKSIG
		return txscript.NewScriptBuilder().
			AddOp(txscript.OP_DUP).
			AddOp(txscript.OP_HASH160).
			AddData(a.Hash160()[:]).
			AddOp(txscript.OP_EQUALVERIFY).
			AddOp(txscript.OP_CHECKSIG).
			Script()
	case *bchutil.AddressScriptHash:
		// P2SH: OP_HASH160 <script-hash> OP_EQUAL
		return txscript.NewScriptBuilder().
			AddOp(txscript.OP_HASH160).
			AddData(a.Hash160()[:]).
			AddOp(txscript.OP_EQUAL).
			Script()
	default:
		return nil, fmt.Errorf("unsupported BCH address type: %T", addr)
	}
}

