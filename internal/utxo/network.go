package utxo

import (
	"bytes"
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"

	"github.com/vultisig/recipes/engine"
	btcsdk "github.com/vultisig/recipes/sdk/btc"
	vtypes "github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/common"

	"github.com/vultisig/dca/internal/blockchair"
	"github.com/vultisig/dca/internal/types"
)

// Network handles UTXO chain operations (send, swap) for any BTC-like chain.
type Network struct {
	chain      common.Chain
	utxo       *blockchair.Client
	fee        FeeProvider
	swap       *SwapService
	send       *SendService
	signerSend *SignerService
	signerSwap *SignerService
}

// NewNetwork creates a new UTXO Network for the specified chain.
func NewNetwork(
	chain common.Chain,
	fee FeeProvider,
	swap *SwapService,
	send *SendService,
	signerSend *SignerService,
	signerSwap *SignerService,
	utxo *blockchair.Client,
) *Network {
	return &Network{
		chain:      chain,
		utxo:       utxo,
		fee:        fee,
		swap:       swap,
		send:       send,
		signerSend: signerSend,
		signerSwap: signerSwap,
	}
}

// Swap performs a cross-chain swap from this UTXO chain.
func (n *Network) Swap(ctx context.Context, policy vtypes.PluginPolicy, from From, to To) (string, error) {
	if to.Chain == n.chain {
		return "", fmt.Errorf("can't swap %s to %s", n.chain.String(), n.chain.String())
	}

	changeOutputIndex, _, outputs, err := n.swap.FindBestAmountOut(ctx, from, to)
	if err != nil {
		return "", fmt.Errorf("find best amount out: %w", err)
	}

	psbtTx, err := n.buildPSBT(ctx, from, outputs, changeOutputIndex)
	if err != nil {
		return "", fmt.Errorf("failed to build psbt: %w", err)
	}

	txHash, err := n.sendWithSdk(ctx, policy, types.OperationSwap, psbtTx)
	if err != nil {
		return "", fmt.Errorf("failed to send tx: %w", err)
	}
	return txHash, nil
}

// Send sends coins using the provided UTXOs and returns the used UTXOs and change UTXO.
// The changeUTXO can be used immediately for subsequent sends (spending unconfirmed change).
func (n *Network) Send(
	ctx context.Context,
	policy vtypes.PluginPolicy,
	from From,
	toAddress string,
	amount uint64,
	availableUTXOs []btcsdk.UTXO,
) (txHash string, usedUTXOs []btcsdk.UTXO, changeUTXO *btcsdk.UTXO, err error) {
	outputs, changeOutputIndex, err := n.send.BuildTransfer(toAddress, from.Address, amount)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to build transfer outputs: %w", err)
	}

	buildResult, err := n.buildPSBTWithUTXOs(ctx, from, outputs, changeOutputIndex, availableUTXOs)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to build psbt: %w", err)
	}

	hash, err := n.sendWithSdk(ctx, policy, types.OperationSend, buildResult.Packet)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to send tx: %w", err)
	}

	// Construct change UTXO if there's change
	if buildResult.ChangeAmount > 0 {
		changeUTXO = &btcsdk.UTXO{
			TxHash: hash,
			Index:  uint32(buildResult.ChangeIndex),
			Value:  uint64(buildResult.ChangeAmount),
		}
	}

	return hash, buildResult.SelectedUTXOs, changeUTXO, nil
}

// FetchUTXOs fetches all unspent outputs for an address and converts to SDK format.
func (n *Network) FetchUTXOs(ctx context.Context, address string) ([]btcsdk.UTXO, error) {
	blockchairUtxos, err := n.utxo.GetAllUnspent(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("failed to get UTXOs: %w", err)
	}

	utxos := make([]btcsdk.UTXO, len(blockchairUtxos))
	for i, u := range blockchairUtxos {
		utxos[i] = btcsdk.UTXO{
			TxHash: u.TransactionHash,
			Index:  u.Index,
			Value:  u.Value,
		}
	}
	return utxos, nil
}

// UpdateAvailableUTXOs removes used UTXOs and adds the change UTXO (if any) to the available list.
func UpdateAvailableUTXOs(available, used []btcsdk.UTXO, change *btcsdk.UTXO) []btcsdk.UTXO {
	usedSet := make(map[string]struct{}, len(used))
	for _, u := range used {
		key := fmt.Sprintf("%s:%d", u.TxHash, u.Index)
		usedSet[key] = struct{}{}
	}

	result := make([]btcsdk.UTXO, 0, len(available)-len(used)+1)
	for _, u := range available {
		key := fmt.Sprintf("%s:%d", u.TxHash, u.Index)
		if _, ok := usedSet[key]; !ok {
			result = append(result, u)
		}
	}

	// Add change UTXO if present (allows spending unconfirmed change)
	if change != nil {
		result = append(result, *change)
	}

	return result
}

// buildPSBTWithUTXOs builds a PSBT using the provided UTXOs instead of fetching them.
// Returns the full BuildResult containing PSBT, selected UTXOs, and change info.
func (n *Network) buildPSBTWithUTXOs(
	ctx context.Context,
	from From,
	outputs []*wire.TxOut,
	changeOutputIndex int,
	availableUTXOs []btcsdk.UTXO,
) (*btcsdk.BuildResult, error) {
	satsPerByte, err := n.fee.SatsPerByte(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get sats per byte: %w", err)
	}

	builder := n.getBuilder()
	
	result, err := builder.Build(availableUTXOs, outputs, changeOutputIndex, satsPerByte, from.PubKey)
	if err != nil {
		return nil, fmt.Errorf("[%s] failed to build tx: %w", n.chain.String(), err)
	}

	err = btcsdk.PopulatePSBTMetadata(result, n.utxo)
	if err != nil {
		return nil, fmt.Errorf("failed to populate psbt metadata: %w", err)
	}

	return result, nil
}

func (n *Network) buildPSBT(
	ctx context.Context,
	from From,
	outputs []*wire.TxOut,
	changeOutputIndex int,
) (*psbt.Packet, error) {
	satsPerByte, err := n.fee.SatsPerByte(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get sats per byte: %w", err)
	}

	// Fetch all UTXOs
	utxos, err := n.FetchUTXOs(ctx, from.Address.String())
	if err != nil {
		return nil, err
	}

	// Build using SDK with chain-specific parameters
	builder := n.getBuilder()
	
	result, err := builder.Build(utxos, outputs, changeOutputIndex, satsPerByte, from.PubKey)
	if err != nil {
		return nil, fmt.Errorf("[%s] failed to build tx: %w", n.chain.String(), err)
	}

	// Populate PSBT metadata
	err = btcsdk.PopulatePSBTMetadata(result, n.utxo)
	if err != nil {
		return nil, fmt.Errorf("failed to populate psbt metadata: %w", err)
	}

	return result.Packet, nil
}

// getBuilder returns a chain-specific builder with the correct dust limit.
func (n *Network) getBuilder() *btcsdk.Builder {
	switch n.chain {
	case common.Litecoin:
		// Litecoin SegWit dust limit (P2WPKH)
		return btcsdk.NewBuilder(5460)
	case common.Dogecoin:
		// Dogecoin dust limit (1 DOGE minimum to avoid spam)
		return btcsdk.NewBuilder(100000000)
	case common.BitcoinCash:
		// BCH uses same dust limit as BTC (forked from BTC)
		return btcsdk.NewBuilder(546)
	default:
		// Default to Bitcoin mainnet parameters
		return btcsdk.Mainnet()
	}
}

func (n *Network) sendWithSdk(ctx context.Context, policy vtypes.PluginPolicy, op string, tx *psbt.Packet) (string, error) {
	var bufPsbt bytes.Buffer
	err := tx.Serialize(&bufPsbt)
	if err != nil {
		return "", fmt.Errorf("failed to serialize psbt: %w", err)
	}

	var bufWireTx bytes.Buffer
	err = tx.UnsignedTx.Serialize(&bufWireTx)
	if err != nil {
		return "", fmt.Errorf("failed to serialize tx.UnsignedTx: %w", err)
	}

	recipe, err := policy.GetRecipe()
	if err != nil {
		return "", fmt.Errorf("failed to unpack recipe: %w", err)
	}

	eng, err := engine.NewEngine()
	if err != nil {
		return "", fmt.Errorf("failed to create engine: %w", err)
	}
	_, err = eng.Evaluate(recipe, n.chain, bufWireTx.Bytes())
	if err != nil {
		return "", fmt.Errorf("failed to evaluate tx: %w", err)
	}

	var txHash string
	switch op {
	case types.OperationSend:
		txHash, err = n.signerSend.SignAndBroadcast(ctx, policy, bufPsbt.Bytes())
		if err != nil {
			return "", fmt.Errorf("[%s] failed to sign and broadcast: %w", n.chain.String(), err)
		}
	case types.OperationSwap:
		txHash, err = n.signerSwap.SignAndBroadcast(ctx, policy, bufPsbt.Bytes())
		if err != nil {
			return "", fmt.Errorf("[%s] failed to sign and broadcast: %w", n.chain.String(), err)
		}
	default:
		return "", fmt.Errorf("[%s] no signer for operation %s", n.chain.String(), op)
	}

	return txHash, nil
}

