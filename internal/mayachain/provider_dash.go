package mayachain

import (
	"context"
	"fmt"
	"math"
	"strconv"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	dashpkg "github.com/vultisig/dca/internal/dash"
	"github.com/vultisig/vultisig-go/common"
)

// ProviderDash implements the Dash swap provider for MayaChain
type ProviderDash struct {
	client *Client
}

// NewProviderDash creates a new Dash provider for MayaChain swaps
func NewProviderDash(client *Client) *ProviderDash {
	return &ProviderDash{
		client: client,
	}
}

func (p *ProviderDash) validateDash(from dashpkg.From, to dashpkg.To) error {
	if to.Chain == common.Dash {
		return fmt.Errorf("can't swap DASH to DASH")
	}

	_, err := parseMayaNetwork(to.Chain)
	if err != nil {
		return fmt.Errorf("unsupported 'to' chain for MayaChain: %w", err)
	}

	return nil
}

// SatsPerByte returns the current fee rate for Dash transactions
func (p *ProviderDash) SatsPerByte(ctx context.Context) (uint64, error) {
	info, err := p.client.getInboundAddresses(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get inbound addresses: %w", err)
	}

	for _, addr := range info {
		if addr.Chain == dash {
			satsPerByte, er := strconv.ParseUint(addr.GasRate, 10, 64)
			if er != nil {
				return 0, fmt.Errorf("failed to parse gas rate: %w", er)
			}
			return satsPerByte, nil
		}
	}
	return 0, fmt.Errorf("no gas info found for DASH")
}

// ChangeOutputIndex returns the index of the change output in swap transactions
func (p *ProviderDash) ChangeOutputIndex() int {
	return 1
}

// MakeOutputs creates transaction outputs for a MayaChain swap
func (p *ProviderDash) MakeOutputs(
	ctx context.Context,
	from dashpkg.From,
	to dashpkg.To,
) (uint64, []*wire.TxOut, error) {
	if err := p.validateDash(from, to); err != nil {
		return 0, nil, fmt.Errorf("invalid swap: %w", err)
	}

	toAsset, err := makeMayaAsset(ctx, p.client, to.Chain, to.AssetID)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to convert maya asset: %w", err)
	}

	quote, err := p.client.getQuote(ctx, quoteSwapRequest{
		FromAsset:         string(dash) + "." + string(dash),
		ToAsset:           toAsset,
		Amount:            fmt.Sprintf("%d", from.Amount),
		Destination:       to.Address,
		StreamingInterval: defaultStreamingInterval,
		StreamingQuantity: defaultStreamingQuantity,
	})
	if err != nil {
		return 0, nil, fmt.Errorf("failed to get quote: %w", err)
	}

	// Create P2PKH script for MayaChain inbound address
	inboundScript, err := createDashP2PKHScript(quote.InboundAddress)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create inbound script: %w", err)
	}

	// Create P2PKH script for change address
	changeScript, err := createDashP2PKHScript(from.Address.String())
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create change script: %w", err)
	}

	// Create OP_RETURN script for memo
	memoScript, err := txscript.NullDataScript([]byte(quote.Memo))
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

	if from.Amount > math.MaxInt64 {
		return 0, nil, fmt.Errorf("dash: amount %d exceeds maximum int64 value", from.Amount)
	}

	outputs := []*wire.TxOut{
		{
			Value:    int64(from.Amount),
			PkScript: inboundScript,
		},
		{
			Value:    0, // Change amount will be calculated later
			PkScript: changeScript,
		},
		{
			Value:    0,
			PkScript: memoScript,
		},
	}

	return expectedOut, outputs, nil
}

// createDashP2PKHScript creates a P2PKH script for a Dash address
func createDashP2PKHScript(address string) ([]byte, error) {
	// Dash addresses start with 'X' for P2PKH
	// Decode the address and create a P2PKH script
	if len(address) == 0 {
		return nil, fmt.Errorf("empty address")
	}

	// Use btcsuite to decode and create script
	// Note: Dash uses different address version bytes but similar P2PKH structure
	decoded, err := decodeBase58Check(address)
	if err != nil {
		return nil, fmt.Errorf("failed to decode address: %w", err)
	}

	if len(decoded) < 21 {
		return nil, fmt.Errorf("decoded address too short")
	}

	// Create P2PKH script: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
	pubKeyHash := decoded[1:21] // Skip version byte
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_DUP)
	builder.AddOp(txscript.OP_HASH160)
	builder.AddData(pubKeyHash)
	builder.AddOp(txscript.OP_EQUALVERIFY)
	builder.AddOp(txscript.OP_CHECKSIG)

	return builder.Script()
}

// decodeBase58Check decodes a Base58Check encoded string with checksum verification
func decodeBase58Check(encoded string) ([]byte, error) {
	// Use btcutil/base58 for proper checksum verification
	decoded, version, err := base58.CheckDecode(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base58check: %w", err)
	}
	// Prepend version byte to match expected format (version + pubKeyHash)
	return append([]byte{version}, decoded...), nil
}


