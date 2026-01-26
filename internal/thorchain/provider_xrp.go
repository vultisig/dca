package thorchain

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	xrpgo "github.com/xyield/xrpl-go/binary-codec"
	xrp_swap "github.com/vultisig/app-recurring/internal/xrp"
	"github.com/vultisig/vultisig-go/common"
)

type ProviderXrp struct {
	client    *Client
	xrpClient interface {
		GetCurrentLedger(ctx context.Context) (uint32, error)
		GetBaseFee(ctx context.Context) (uint64, error)
	}
}

func NewProviderXrp(client *Client, xrpClient interface {
	GetCurrentLedger(ctx context.Context) (uint32, error)
	GetBaseFee(ctx context.Context) (uint64, error)
}) *ProviderXrp {
	return &ProviderXrp{
		client:    client,
		xrpClient: xrpClient,
	}
}

func (p *ProviderXrp) validateXrp(from xrp_swap.From, to xrp_swap.To) error {
	if to.Chain == common.XRP {
		return fmt.Errorf("[XRP] can't swap XRP to XRP")
	}

	_, err := parseThorNetwork(to.Chain)
	if err != nil {
		return fmt.Errorf("[XRP] unsupported 'to' chain: %w", err)
	}

	return nil
}

// asciiToHex converts ASCII to lowercase hex (XRPL expects hex in Memo fields)
func asciiToHex(s string) string {
	return hex.EncodeToString([]byte(s))
}

// buildThorMemo assembles "=:ASSET:DEST_ADDR:LIM/affiliate" from quote data
func buildThorMemo(toAsset, destAddr string) string {
	memo := "=:" + toAsset + ":" + destAddr
	// Note: limit and affiliate are typically handled by THORChain quote
	return memo
}

// buildUnsignedXRPLThorSwapTx creates an unsigned Payment with THOR memo
func buildUnsignedXRPLThorSwapTx(
	from string,
	vaultAddress string, // THORChain inbound XRP address
	amountDrops uint64,
	sequence uint32,
	feeDrops uint64,
	lastLedgerSequence uint32,
	thorMemo string, // raw ASCII THOR memo
	signingPubKey string, // 33-byte compressed public key in hex
) ([]byte, error) {
	memoHex := asciiToHex(thorMemo)

	memos := []any{
		map[string]any{
			"Memo": map[string]any{
				"MemoData": memoHex,                      // required: hex data
				"MemoType": asciiToHex("thorchain-memo"), // optional, nice to have
			},
		},
	}

	jsonMap := map[string]any{
		"Account":            from,
		"TransactionType":    "Payment",
		"Amount":             fmt.Sprintf("%d", amountDrops), // drops as string
		"Destination":        vaultAddress,
		"Fee":                fmt.Sprintf("%d", feeDrops), // drops as string
		"Sequence":           int(sequence),
		"LastLedgerSequence": int(lastLedgerSequence),
		"SigningPubKey":      strings.ToUpper(strings.TrimSpace(signingPubKey)),
		"Memos":              memos,
	}

	// Encode → Decode → Re-encode for canonical bytes
	hexStr, err := xrpgo.Encode(jsonMap)
	if err != nil {
		return nil, fmt.Errorf("encode failed: %w", err)
	}

	decoded, err := xrpgo.Decode(strings.ToUpper(hexStr))
	if err != nil {
		return nil, fmt.Errorf("decode round-trip failed: %w", err)
	}

	canonicalHex, err := xrpgo.Encode(decoded)
	if err != nil {
		return nil, fmt.Errorf("re-encode failed: %w", err)
	}

	txBytes, err := hex.DecodeString(canonicalHex)
	if err != nil {
		return nil, fmt.Errorf("hex to bytes failed: %w", err)
	}

	return txBytes, nil
}

func (p *ProviderXrp) MakeTransaction(
	ctx context.Context,
	from xrp_swap.From,
	to xrp_swap.To,
) ([]byte, uint64, error) {
	if err := p.validateXrp(from, to); err != nil {
		return nil, 0, fmt.Errorf("[XRP] invalid swap: %w", err)
	}

	// Convert from asset to THORChain format
	fromAsset, err := makeThorAsset(ctx, p.client, common.XRP, from.AssetID)
	if err != nil {
		return nil, 0, fmt.Errorf("[XRP] failed to convert from thor asset: %w", err)
	}

	toAsset, err := makeThorAsset(ctx, p.client, to.Chain, to.AssetID)
	if err != nil {
		return nil, 0, fmt.Errorf("[XRP] failed to convert to thor asset: %w", err)
	}

	// Convert XRP drops (6 decimals) to THORChain units (8 decimals)
	// XRP: 1 XRP = 1,000,000 drops (10^6)
	// THORChain: uses 8 decimals for all assets
	// Multiply by 100 (10^2) to convert: 10^6 * 10^2 = 10^8
	thorchainAmount := from.Amount * 100

	quote, err := p.client.getQuote(ctx, quoteSwapRequest{
		FromAsset:         fromAsset,
		ToAsset:           toAsset,
		Amount:            fmt.Sprintf("%d", thorchainAmount),
		Destination:       to.Address,
		StreamingInterval: defaultStreamingInterval,
		StreamingQuantity: defaultStreamingQuantity,
		//ToleranceBps:      defaultToleranceBps,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("[XRP] failed to get THORChain quote: %w", err)
	}

	// Parse expected amount out
	expectedOut, err := strconv.ParseUint(quote.ExpectedAmountOut, 10, 64)
	if err != nil {
		return nil, 0, fmt.Errorf("[XRP] failed to parse expected amount out: %w", err)
	}

	// Get dynamic data from XRP client
	currentLedger, err := p.xrpClient.GetCurrentLedger(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("[XRP] failed to get current ledger: %w", err)
	}
	
	baseFee, err := p.xrpClient.GetBaseFee(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("[XRP] failed to get base fee: %w", err)
	}

	// Calculate dynamic values
	sequence := from.Sequence                  // Already fetched by Network.Swap
	feeDrops := baseFee + 3                    // Add buffer for memo transaction
	lastLedgerSeq := currentLedger + 100       // 100 ledger buffer (~5 minutes)

	// Build THORChain memo (use quote memo if available, otherwise construct)
	var thorMemo string
	if quote.Memo != "" {
		thorMemo = quote.Memo
	} else {
		thorMemo = buildThorMemo(toAsset, to.Address)
	}

	// Build unsigned XRP transaction
	txBytes, err := buildUnsignedXRPLThorSwapTx(
		from.Address,
		quote.InboundAddress, // THORChain vault address
		from.Amount,
		sequence,
		feeDrops,
		lastLedgerSeq,
		thorMemo,
		from.PubKey, // Child-derived pubkey
	)
	if err != nil {
		return nil, 0, fmt.Errorf("[XRP] failed to build XRP transaction: %w", err)
	}

	return txBytes, expectedOut, nil
}