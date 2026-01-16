package thorchain

import (
	"context"
	"fmt"
	"strconv"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	ltcchaincfg "github.com/ltcsuite/ltcd/chaincfg"
	"github.com/ltcsuite/ltcd/ltcutil"

	utxo_swap "github.com/vultisig/dca/internal/utxo"
	"github.com/vultisig/vultisig-go/common"
)

// ProviderLtc implements FeeProvider and SwapProvider for Litecoin via THORChain.
type ProviderLtc struct {
	client *Client
}

// NewProviderLtc creates a new Litecoin provider for THORChain swaps.
func NewProviderLtc(client *Client) *ProviderLtc {
	return &ProviderLtc{
		client: client,
	}
}

func (p *ProviderLtc) validateLtc(from utxo_swap.From, to utxo_swap.To) error {
	if to.Chain == common.Litecoin {
		return fmt.Errorf("[LTC] can't swap LTC to LTC")
	}

	_, err := parseThorNetwork(to.Chain)
	if err != nil {
		return fmt.Errorf("[LTC] unsupported 'to' chain: %w", err)
	}

	return nil
}

// SatsPerByte returns the current fee rate for Litecoin from THORChain.
func (p *ProviderLtc) SatsPerByte(ctx context.Context) (uint64, error) {
	info, err := p.client.getInboundAddresses(ctx, inboundAddressesRequest{})
	if err != nil {
		return 0, fmt.Errorf("[LTC] failed to get inbound addresses: %w", err)
	}

	for _, addr := range info {
		if addr.Chain == ltc {
			satsPerByte, er := strconv.ParseUint(addr.GasRate, 10, 64)
			if er != nil {
				return 0, fmt.Errorf("[LTC] failed to parse gas rate: %w", er)
			}
			return satsPerByte, nil
		}
	}
	return 0, fmt.Errorf("[LTC] no gas info found for Litecoin")
}

// ChangeOutputIndex returns the index of the change output in swap transactions.
func (p *ProviderLtc) ChangeOutputIndex() int {
	return 1
}

// MakeOutputs builds the transaction outputs for a Litecoin to X swap via THORChain.
func (p *ProviderLtc) MakeOutputs(
	ctx context.Context,
	from utxo_swap.From,
	to utxo_swap.To,
) (uint64, []*wire.TxOut, error) {
	if err := p.validateLtc(from, to); err != nil {
		return 0, nil, fmt.Errorf("[LTC] invalid swap: %w", err)
	}

	toAsset, err := makeThorAsset(ctx, p.client, to.Chain, to.AssetID)
	if err != nil {
		return 0, nil, fmt.Errorf("[LTC] failed to convert thor asset: %w", err)
	}

	quote, err := p.client.getQuote(ctx, quoteSwapRequest{
		FromAsset:         string(ltc) + "." + string(ltc),
		ToAsset:           toAsset,
		Amount:            fmt.Sprintf("%d", from.Amount),
		Destination:       to.Address,
		StreamingInterval: defaultStreamingInterval,
		StreamingQuantity: defaultStreamingQuantity,
	})
	if err != nil {
		return 0, nil, fmt.Errorf("[LTC] failed to get quote: %w", err)
	}

	// Decode the THORChain inbound address using Litecoin network params
	inboundAddr, err := ltcutil.DecodeAddress(quote.InboundAddress, &ltcchaincfg.MainNetParams)
	if err != nil {
		return 0, nil, fmt.Errorf("[LTC] failed to decode inbound address: %w", err)
	}

	inboundScript, err := ltcPayToAddrScript(inboundAddr)
	if err != nil {
		return 0, nil, fmt.Errorf("[LTC] failed to create inbound script: %w", err)
	}

	changeScript, err := from.Address.PayToAddrScript()
	if err != nil {
		return 0, nil, fmt.Errorf("[LTC] failed to create change script: %w", err)
	}

	memoScript, err := createMemoScript(quote.Memo)
	if err != nil {
		return 0, nil, fmt.Errorf("[LTC] failed to create memo script: %w", err)
	}

	expectedOut, err := strconv.ParseUint(quote.ExpectedAmountOut, 10, 64)
	if err != nil {
		return 0, nil, fmt.Errorf("[LTC] failed to parse expected amount out: %w", err)
	}

	dustThreshold, err := strconv.ParseUint(quote.DustThreshold, 10, 64)
	if err != nil {
		return 0, nil, fmt.Errorf("[LTC] failed to parse dust threshold: %w", err)
	}

	if from.Amount < dustThreshold {
		return 0, nil, fmt.Errorf("[LTC] amount %d below dust threshold %d", from.Amount, dustThreshold)
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

// ltcPayToAddrScript creates a pay-to-address script for Litecoin addresses.
func ltcPayToAddrScript(addr ltcutil.Address) ([]byte, error) {
	// For SegWit addresses (P2WPKH), we need to create the witness program script
	switch a := addr.(type) {
	case *ltcutil.AddressWitnessPubKeyHash:
		// P2WPKH: OP_0 <20-byte-witness-program>
		return txscript.NewScriptBuilder().
			AddOp(txscript.OP_0).
			AddData(a.WitnessProgram()).
			Script()
	case *ltcutil.AddressPubKeyHash:
		// P2PKH: OP_DUP OP_HASH160 <pubkey-hash> OP_EQUALVERIFY OP_CHECKSIG
		return txscript.NewScriptBuilder().
			AddOp(txscript.OP_DUP).
			AddOp(txscript.OP_HASH160).
			AddData(a.Hash160()[:]).
			AddOp(txscript.OP_EQUALVERIFY).
			AddOp(txscript.OP_CHECKSIG).
			Script()
	case *ltcutil.AddressScriptHash:
		// P2SH: OP_HASH160 <script-hash> OP_EQUAL
		return txscript.NewScriptBuilder().
			AddOp(txscript.OP_HASH160).
			AddData(a.Hash160()[:]).
			AddOp(txscript.OP_EQUAL).
			Script()
	default:
		// Fall back to btcutil if we can decode as a btcutil address
		btcAddr, err := btcutil.DecodeAddress(addr.String(), nil)
		if err != nil {
			return nil, fmt.Errorf("unsupported LTC address type: %T", addr)
		}
		return txscript.PayToAddrScript(btcAddr)
	}
}

