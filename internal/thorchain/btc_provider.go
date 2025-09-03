package thorchain

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	btc_swap "github.com/vultisig/dca/internal/btc"
	"github.com/vultisig/vultisig-go/common"
)

type BtcProvider struct {
	client *Client
}

func NewBtcProvider(client *Client) *BtcProvider {
	return &BtcProvider{
		client: client,
	}
}

func (p *BtcProvider) validateBtc(from btc_swap.From, to btc_swap.To) error {
	if to.Chain == common.Bitcoin {
		return fmt.Errorf("can't swap btc to btc")
	}

	_, err := toThor(to.Chain)
	if err != nil {
		return fmt.Errorf("unsupported 'to' chain: %w", err)
	}

	switch from.Address.(type) {
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

func (p *BtcProvider) SatsPerByte(ctx context.Context) (uint64, error) {
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

func (p *BtcProvider) ChangeOutputIndex() int {
	return 1
}

func (p *BtcProvider) makeThorAsset(ctx context.Context, chain common.Chain, asset string) (string, error) {
	thorNet, err := toThor(chain)
	if err != nil {
		return "", fmt.Errorf("unsupported chain: %w", err)
	}

	// Check if asset is native token
	if asset == "" {
		// Native token format: Network.TokenSymbol (e.g., AVAX.AVAX)
		nativeSymbol, er := chain.NativeSymbol()
		if er != nil {
			return "", fmt.Errorf("failed to get native symbol for chain %s: %w", chain, er)
		}
		return string(thorNet) + "." + nativeSymbol, nil
	}

	// For tokens, find the full asset string from THORChain pools
	// Format: Network.TokenSymbol-Asset (e.g., AVAX.SOL-0XFE6B19286885A4F7F55ADAD09C3CD1F906D2478F)
	pools, err := p.client.getPools(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get pools: %w", err)
	}

	networkPrefix := string(thorNet) + "."
	targetAsset := strings.ToUpper(asset)

	for _, pp := range pools {
		// Check if pool belongs to our network
		if !strings.HasPrefix(pp.Asset, networkPrefix) {
			continue
		}

		// Split the asset into parts: Network.TokenSymbol-Asset
		parts := strings.Split(pp.Asset, ".")
		if len(parts) != 2 {
			continue
		}

		// Check if the second part contains a dash (indicating token with address)
		tokenPart := parts[1]
		if !strings.Contains(tokenPart, "-") {
			continue
		}

		// Split token part: TokenSymbol-Address
		tokenParts := strings.Split(tokenPart, "-")
		if len(tokenParts) != 2 {
			continue
		}

		// Check if the address matches (case-insensitive)
		poolAddress := tokenParts[1]
		if strings.EqualFold(poolAddress, targetAsset) {
			return pp.Asset, nil
		}
	}

	return "", fmt.Errorf("asset not found in THORChain pools for chain %s and asset %s", thorNet, asset)
}

func (p *BtcProvider) MakeOutputs(
	ctx context.Context,
	from btc_swap.From,
	to btc_swap.To,
) (uint64, []*wire.TxOut, error) {
	if err := p.validateBtc(from, to); err != nil {
		return 0, nil, fmt.Errorf("invalid swap: %w", err)
	}

	toAsset, err := p.makeThorAsset(ctx, to.Chain, to.AssetID)
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
		ToleranceBps:      defaultToleranceBps,
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

	changeScript, err := payToAddrScript(from.Address)
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
	return txscript.NullDataScript([]byte(memo))
}
