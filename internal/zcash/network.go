package zcash

import (
	"cmp"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"github.com/vultisig/recipes/engine"
	"github.com/vultisig/recipes/sdk/zcash"
	vtypes "github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/common"
)

// Network handles Zcash transaction building, signing, and broadcasting
type Network struct {
	utxo       UtxoProvider
	fee        feeProvider
	swap       *SwapService
	send       *SendService
	signerSend *SignerService
	signerSwap *SignerService
	sdk        *zcash.SDK
}

// NewNetwork creates a new Zcash network handler
func NewNetwork(
	fee feeProvider,
	swap *SwapService,
	send *SendService,
	signerSend *SignerService,
	signerSwap *SignerService,
	utxo UtxoProvider,
) *Network {
	return &Network{
		utxo:       utxo,
		fee:        fee,
		swap:       swap,
		send:       send,
		signerSend: signerSend,
		signerSwap: signerSwap,
		sdk:        zcash.NewSDK(nil), // SDK without broadcaster (used only for tx building)
	}
}

// Swap executes a swap from ZEC to another asset
func (n *Network) Swap(ctx context.Context, policy vtypes.PluginPolicy, from From, to To) (string, error) {
	if to.Chain == common.Zcash {
		return "", errors.New("zcash: can't swap ZEC to ZEC")
	}

	changeOutputIndex, _, outputs, err := n.swap.FindBestAmountOut(ctx, from, to)
	if err != nil {
		return "", fmt.Errorf("zcash: find best amount out: %w", err)
	}

	unsignedTx, err := n.buildUnsignedTx(ctx, from, outputs, changeOutputIndex)
	if err != nil {
		return "", fmt.Errorf("zcash: failed to build tx: %w", err)
	}

	// Evaluate transaction against policy rules
	recipe, err := policy.GetRecipe()
	if err != nil {
		return "", fmt.Errorf("zcash: failed to unpack recipe: %w", err)
	}

	eng, err := engine.NewEngine()
	if err != nil {
		return "", fmt.Errorf("zcash: failed to create engine: %w", err)
	}
	_, err = eng.Evaluate(recipe, common.Zcash, unsignedTx.RawBytes)
	if err != nil {
		return "", fmt.Errorf("zcash: failed to evaluate tx: %w", err)
	}

	txHash, err := n.signerSwap.SignAndBroadcast(ctx, policy, unsignedTx)
	if err != nil {
		return "", fmt.Errorf("zcash: failed to sign and broadcast: %w", err)
	}

	return txHash, nil
}

// Send executes a simple ZEC transfer
func (n *Network) Send(
	ctx context.Context,
	policy vtypes.PluginPolicy,
	from From,
	toAddress string,
	amount uint64,
) (string, error) {
	outputs, changeOutputIndex, err := n.send.BuildTransfer(toAddress, from.Address, amount)
	if err != nil {
		return "", fmt.Errorf("zcash: failed to build transfer outputs: %w", err)
	}

	unsignedTx, err := n.buildUnsignedTx(ctx, from, outputs, changeOutputIndex)
	if err != nil {
		return "", fmt.Errorf("zcash: failed to build tx: %w", err)
	}

	// Evaluate transaction against policy rules
	recipe, err := policy.GetRecipe()
	if err != nil {
		return "", fmt.Errorf("zcash: failed to unpack recipe: %w", err)
	}

	eng, err := engine.NewEngine()
	if err != nil {
		return "", fmt.Errorf("zcash: failed to create engine: %w", err)
	}
	_, err = eng.Evaluate(recipe, common.Zcash, unsignedTx.RawBytes)
	if err != nil {
		return "", fmt.Errorf("zcash: failed to evaluate tx: %w", err)
	}

	txHash, err := n.signerSend.SignAndBroadcast(ctx, policy, unsignedTx)
	if err != nil {
		return "", fmt.Errorf("zcash: failed to sign and broadcast: %w", err)
	}

	return txHash, nil
}

// buildUnsignedTx builds an unsigned transaction with UTXOs and calculates signature hashes
func (n *Network) buildUnsignedTx(
	ctx context.Context,
	from From,
	outputs []*TxOutput,
	changeOutputIndex int,
) (*UnsignedTx, error) {
	if changeOutputIndex < 0 || changeOutputIndex >= len(outputs) {
		return nil, fmt.Errorf("zcash: invalid change output index %d for %d outputs", changeOutputIndex, len(outputs))
	}

	if _, err := n.fee.ZatoshisPerByte(ctx); err != nil {
		return nil, fmt.Errorf("zcash: failed to get zatoshis per byte: %w", err)
	}

	utxoCtx, utxoCtxCancel := context.WithCancel(ctx)
	defer utxoCtxCancel()
	utxoCh := n.utxo.GetUnspent(utxoCtx, from.Address)

	var inputs []TxInput
	var totalInputsValue uint64

	// Get the script for from address (for signing)
	fromScript, err := PayToAddrScript(from.Address)
	if err != nil {
		return nil, fmt.Errorf("zcash: failed to get from address script: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case utxoBatch, ok := <-utxoCh:
			if !ok {
				return nil, fmt.Errorf("zcash: insufficient UTXOs (have %d, need %d)", totalInputsValue, from.Amount)
			}
			if utxoBatch.Err != nil {
				return nil, fmt.Errorf("zcash: failed to get utxos: %w", utxoBatch.Err)
			}

			slices.SortFunc(utxoBatch.Utxos, func(a, b Utxo) int {
				return cmp.Compare(b.Value, a.Value)
			})

			for _, u := range utxoBatch.Utxos {
				input := TxInput{
					TxHash:   u.TransactionHash,
					Index:    u.Index,
					Value:    u.Value,
					Script:   fromScript,
					Sequence: 0xffffffff,
				}

				inputs = append(inputs, input)
				totalInputsValue += u.Value

				fee := estimateFee(len(inputs), outputs)
				if totalInputsValue > from.Amount+fee {
					changeValue := int64(totalInputsValue - from.Amount - fee)
					outputs[changeOutputIndex].Value = changeValue

					utxoCtxCancel()
					<-utxoCh // Drain channel after cancel

					return n.finalizeUnsignedTx(inputs, outputs, from.PubKey)
				}
			}
		}
	}
}

// finalizeUnsignedTx creates the final unsigned transaction structure
func (n *Network) finalizeUnsignedTx(inputs []TxInput, outputs []*TxOutput, pubKey []byte) (*UnsignedTx, error) {
	// Convert to SDK types for serialization
	sdkInputs := toSDKInputs(inputs)
	sdkOutputs := toSDKOutputs(outputs)

	rawBytes, err := n.sdk.SerializeUnsignedTx(sdkInputs, sdkOutputs)
	if err != nil {
		return nil, fmt.Errorf("zcash: failed to serialize tx: %w", err)
	}

	// Calculate signature hashes for each input using the SDK
	sigHashes := make([][]byte, len(inputs))
	for i := range inputs {
		sigHash, err := n.sdk.CalculateSigHash(sdkInputs, sdkOutputs, i)
		if err != nil {
			return nil, fmt.Errorf("zcash: failed to calculate sig hash for input %d: %w", i, err)
		}
		sigHashes[i] = sigHash
	}

	return &UnsignedTx{
		Inputs:    inputs,
		Outputs:   outputs,
		PubKey:    pubKey,
		RawBytes:  rawBytes,
		SigHashes: sigHashes,
	}, nil
}

// toSDKInputs converts local TxInputs to SDK TxInputs
func toSDKInputs(inputs []TxInput) []zcash.TxInput {
	sdkInputs := make([]zcash.TxInput, len(inputs))
	for i, in := range inputs {
		sdkInputs[i] = zcash.TxInput{
			TxHash:   in.TxHash,
			Index:    in.Index,
			Value:    in.Value,
			Script:   in.Script,
			Sequence: in.Sequence,
		}
	}
	return sdkInputs
}

// toSDKOutputs converts local TxOutputs to SDK TxOutputs
func toSDKOutputs(outputs []*TxOutput) []*zcash.TxOutput {
	sdkOutputs := make([]*zcash.TxOutput, len(outputs))
	for i, out := range outputs {
		sdkOutputs[i] = &zcash.TxOutput{
			Value:  out.Value,
			Script: out.Script,
		}
	}
	return sdkOutputs
}

// estimateFee estimates the transaction fee based on ZIP-317 logical actions.
// ZIP-317 requires: conventional_fee = marginal_fee × max(grace_actions, logical_actions)
// where marginal_fee = 5000 zatoshis, grace_actions = 2
// For transparent-only txs: logical_actions = max(ceil(input_bytes/150), ceil(output_bytes/34))
// See: https://zips.z.cash/zip-0317
func estimateFee(numInputs int, outputs []*TxOutput) uint64 {
	const (
		marginalFee          = 5000 // zatoshis per logical action
		graceActions         = 2    // minimum actions charged
		p2pkhInputSize       = 150  // standard P2PKH input size
		p2pkhOutputSize      = 34   // standard P2PKH output size (8 value + 1 len + 25 script)
	)

	// Calculate total output size (value + compactSize + script for each output)
	totalOutputSize := 0
	for _, out := range outputs {
		// 8 bytes for value + 1 byte for script length (assuming < 253) + script length
		totalOutputSize += 8 + 1 + len(out.Script)
	}

	// Input actions = ceil(total_input_bytes / 150)
	totalInputSize := numInputs * p2pkhInputSize
	inputActions := (totalInputSize + p2pkhInputSize - 1) / p2pkhInputSize

	// Output actions = ceil(total_output_bytes / 34)
	outputActions := (totalOutputSize + p2pkhOutputSize - 1) / p2pkhOutputSize

	// Logical actions = max(input_actions, output_actions)
	logicalActions := inputActions
	if outputActions > logicalActions {
		logicalActions = outputActions
	}

	// Fee = marginal_fee × max(grace_actions, logical_actions)
	actions := graceActions
	if logicalActions > actions {
		actions = logicalActions
	}

	return uint64(marginalFee * actions)
}

// GetAddressFromPubKey generates a Zcash address from a hex-encoded public key
func GetAddressFromPubKey(hexPubKey string) (string, []byte, error) {
	pubKeyBytes, err := hex.DecodeString(hexPubKey)
	if err != nil {
		return "", nil, fmt.Errorf("zcash: invalid hex public key: %w", err)
	}

	if len(pubKeyBytes) != 33 {
		return "", nil, fmt.Errorf("zcash: invalid public key length: expected 33 bytes, got %d", len(pubKeyBytes))
	}

	addr, err := GetAddressFromPublicKey(pubKeyBytes)
	if err != nil {
		return "", nil, fmt.Errorf("zcash: failed to get address: %w", err)
	}

	return addr, pubKeyBytes, nil
}
