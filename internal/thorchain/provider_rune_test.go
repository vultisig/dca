package thorchain

import (
	"context"
	"testing"
	"time"

	rune_swap "github.com/vultisig/app-recurring/internal/rune"
	"github.com/vultisig/vultisig-go/common"
)

func TestProviderRune_MakeTransaction_RUNEtoETH(t *testing.T) {
	thorClient := NewClient("https://thornode.ninerealms.com")
	provider := NewProviderRune(thorClient, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	from := rune_swap.From{
		Address:       "thor1ujn87mrfqqw4aksn9w8ggfl2zfaypdgxhax0qj",
		Amount:        2000000000, // 20 RUNE - above minimum swap amount
		PubKey:        "02e5e2b8d8f1a6d3b9c7e1f3a2b4c6d8e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6",
		AccountNumber: 123456,
		Sequence:      0,
		AssetID:       "",
	}

	to := rune_swap.To{
		Chain:   common.Ethereum,
		AssetID: "",
		Address: "0x6507f97E3A26E966bC381153eB16Fa55ED23a38E",
	}

	txData, signBytes, toAmount, err := provider.MakeTransaction(ctx, from, to)
	if err != nil {
		t.Fatalf("MakeTransaction failed: %v", err)
	}

	t.Logf("Transaction built successfully:")
	t.Logf("  txData length: %d bytes", len(txData))
	t.Logf("  signBytes length: %d bytes", len(signBytes))
	t.Logf("  toAmount: %d", toAmount)

	if len(txData) == 0 {
		t.Error("expected txData to be non-empty")
	}
	if len(signBytes) == 0 {
		t.Error("expected signBytes to be non-empty")
	}
	if toAmount == 0 {
		t.Error("expected toAmount to be non-zero")
	}
}

func TestProviderRune_MakeTransaction_RUNEtoBTC(t *testing.T) {
	thorClient := NewClient("https://thornode.ninerealms.com")
	provider := NewProviderRune(thorClient, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	from := rune_swap.From{
		Address:       "thor1ujn87mrfqqw4aksn9w8ggfl2zfaypdgxhax0qj",
		Amount:        2000000000, // 20 RUNE - above minimum swap amount
		PubKey:        "02e5e2b8d8f1a6d3b9c7e1f3a2b4c6d8e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6",
		AccountNumber: 123456,
		Sequence:      0,
		AssetID:       "",
	}

	to := rune_swap.To{
		Chain:   common.Bitcoin,
		AssetID: "",
		Address: "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
	}

	txData, signBytes, toAmount, err := provider.MakeTransaction(ctx, from, to)
	if err != nil {
		t.Fatalf("MakeTransaction failed: %v", err)
	}

	t.Logf("Transaction built successfully:")
	t.Logf("  txData length: %d bytes", len(txData))
	t.Logf("  signBytes length: %d bytes", len(signBytes))
	t.Logf("  toAmount: %d", toAmount)

	if len(txData) == 0 {
		t.Error("expected txData to be non-empty")
	}
	if len(signBytes) == 0 {
		t.Error("expected signBytes to be non-empty")
	}
	if toAmount == 0 {
		t.Error("expected toAmount to be non-zero")
	}
}
