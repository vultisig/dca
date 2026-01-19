package thorchain

import (
	"context"
	"testing"
	"time"
)

func TestGetQuote_RUNEtoETH(t *testing.T) {
	client := NewClient("https://thornode.ninerealms.com")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	quote, err := client.getQuote(ctx, quoteSwapRequest{
		FromAsset:         "THOR.RUNE",
		ToAsset:           "ETH.ETH",
		Amount:            "1000000000",
		Destination:       "0x6507f97E3A26E966bC381153eB16Fa55ED23a38E",
		StreamingInterval: "3",
		StreamingQuantity: "0",
		ToleranceBps:      "2500",
	})
	if err != nil {
		t.Fatalf("failed to get quote: %v", err)
	}

	t.Logf("Quote response:")
	t.Logf("  Memo: %s", quote.Memo)
	t.Logf("  ExpectedAmountOut: %s", quote.ExpectedAmountOut)
	t.Logf("  DustThreshold: %s", quote.DustThreshold)
	t.Logf("  RecommendedMinAmountIn: %s", quote.RecommendedMinAmountIn)
	t.Logf("  InboundAddress: %s", quote.InboundAddress)
	t.Logf("  Router: %s", quote.Router)

	if quote.Memo == "" {
		t.Error("expected memo to be non-empty")
	}
	if quote.ExpectedAmountOut == "" {
		t.Error("expected ExpectedAmountOut to be non-empty")
	}
}

func TestGetQuote_RUNEtoBTC(t *testing.T) {
	client := NewClient("https://thornode.ninerealms.com")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	quote, err := client.getQuote(ctx, quoteSwapRequest{
		FromAsset:         "THOR.RUNE",
		ToAsset:           "BTC.BTC",
		Amount:            "1000000000",
		Destination:       "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
		StreamingInterval: "3",
		StreamingQuantity: "0",
	})
	if err != nil {
		t.Fatalf("failed to get quote: %v", err)
	}

	t.Logf("Quote response:")
	t.Logf("  Memo: %s", quote.Memo)
	t.Logf("  ExpectedAmountOut: %s", quote.ExpectedAmountOut)
	t.Logf("  DustThreshold: %s", quote.DustThreshold)
	t.Logf("  RecommendedMinAmountIn: %s", quote.RecommendedMinAmountIn)

	if quote.Memo == "" {
		t.Error("expected memo to be non-empty")
	}
	if quote.ExpectedAmountOut == "" {
		t.Error("expected ExpectedAmountOut to be non-empty")
	}
}
