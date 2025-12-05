package zcash

import (
	"cmp"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"github.com/vultisig/recipes/engine"
	vtypes "github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/common"
)

// Network handles Zcash transaction building, signing, and broadcasting
type Network struct {
	utxo   UtxoProvider
	fee    feeProvider
	swap   *SwapService
	send   *SendService
	signer *SignerService
}

// NewNetwork creates a new Zcash network handler
func NewNetwork(
	fee feeProvider,
	swap *SwapService,
	send *SendService,
	signer *SignerService,
	utxo UtxoProvider,
) *Network {
	return &Network{
		utxo:   utxo,
		fee:    fee,
		swap:   swap,
		send:   send,
		signer: signer,
	}
}

// Swap executes a swap from ZEC to another asset
func (n *Network) Swap(ctx context.Context, policy vtypes.PluginPolicy, from From, to To) (string, error) {
	if to.Chain == common.Zcash {
		return "", errors.New("can't swap ZEC to ZEC")
	}

	changeOutputIndex, _, outputs, err := n.swap.FindBestAmountOut(ctx, from, to)
	if err != nil {
		return "", fmt.Errorf("find best amount out: %w", err)
	}

	unsignedTx, err := n.buildUnsignedTx(ctx, from, outputs, changeOutputIndex)
	if err != nil {
		return "", fmt.Errorf("failed to build tx: %w", err)
	}

	// Evaluate transaction against policy rules
	recipe, err := policy.GetRecipe()
	if err != nil {
		return "", fmt.Errorf("failed to unpack recipe: %w", err)
	}

	eng, err := engine.NewEngine()
	if err != nil {
		return "", fmt.Errorf("failed to create engine: %w", err)
	}
	_, err = eng.Evaluate(recipe, common.Zcash, unsignedTx.RawBytes)
	if err != nil {
		return "", fmt.Errorf("failed to evaluate tx: %w", err)
	}

	txHash, err := n.signer.SignAndBroadcast(ctx, policy, unsignedTx)
	if err != nil {
		return "", fmt.Errorf("failed to sign and broadcast: %w", err)
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
		return "", fmt.Errorf("failed to build transfer outputs: %w", err)
	}

	unsignedTx, err := n.buildUnsignedTx(ctx, from, outputs, changeOutputIndex)
	if err != nil {
		return "", fmt.Errorf("failed to build tx: %w", err)
	}

	// Evaluate transaction against policy rules
	recipe, err := policy.GetRecipe()
	if err != nil {
		return "", fmt.Errorf("failed to unpack recipe: %w", err)
	}

	eng, err := engine.NewEngine()
	if err != nil {
		return "", fmt.Errorf("failed to create engine: %w", err)
	}
	_, err = eng.Evaluate(recipe, common.Zcash, unsignedTx.RawBytes)
	if err != nil {
		return "", fmt.Errorf("failed to evaluate tx: %w", err)
	}

	txHash, err := n.signer.SignAndBroadcast(ctx, policy, unsignedTx)
	if err != nil {
		return "", fmt.Errorf("failed to sign and broadcast: %w", err)
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
	zatoshisPerByte, err := n.fee.ZatoshisPerByte(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get zatoshis per byte: %w", err)
	}

	utxoCtx, utxoCtxCancel := context.WithCancel(ctx)
	defer utxoCtxCancel()
	utxoCh := n.utxo.GetUnspent(utxoCtx, from.Address)

	var inputs []TxInput
	var totalInputsValue uint64

	// Get the script for from address (for signing)
	fromScript, err := PayToAddrScript(from.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to get from address script: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case utxoBatch, ok := <-utxoCh:
			if !ok {
				return nil, errors.New(
					"utxo channel closed (cannot pick enough utxos to cover desired fromAmount)",
				)
			}
			if utxoBatch.Err != nil {
				return nil, fmt.Errorf("failed to get utxos: %w", utxoBatch.Err)
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

				fee := estimateFee(len(inputs), len(outputs), zatoshisPerByte)
				if totalInputsValue > from.Amount+fee {
					outputs[changeOutputIndex].Value = int64(totalInputsValue - from.Amount - fee)

					utxoCtxCancel()
					_ = <-utxoCh

					return n.finalizeUnsignedTx(inputs, outputs, from.PubKey)
				}
			}
		}
	}
}

// finalizeUnsignedTx creates the final unsigned transaction structure
func (n *Network) finalizeUnsignedTx(inputs []TxInput, outputs []*TxOutput, pubKey []byte) (*UnsignedTx, error) {
	rawBytes, err := SerializeUnsignedTx(inputs, outputs)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize tx: %w", err)
	}

	// Calculate signature hashes for each input
	sigHashes := make([][]byte, len(inputs))
	for i := range inputs {
		sigHash, err := CalculateSigHash(inputs, outputs, i)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate sig hash for input %d: %w", i, err)
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

// estimateFee estimates the transaction fee based on size
func estimateFee(numInputs, numOutputs int, zatoshisPerByte uint64) uint64 {
	// Zcash v5 transaction overhead
	// Version: 4, VersionGroupID: 4, BranchID: 4, LockTime: 4, ExpiryHeight: 4
	// Plus empty sapling/orchard: 3 bytes
	baseSize := 4 + 4 + 4 + 4 + 4 + 3

	// Input size: prevout (32+4) + script (~107 for P2PKH sig) + sequence (4)
	inputSize := (32 + 4 + 107 + 4) * numInputs

	// Output size: value (8) + script (~25 for P2PKH)
	outputSize := (8 + 1 + 25) * numOutputs

	// Add some buffer for varint encoding
	totalSize := baseSize + inputSize + outputSize + 10

	return uint64(totalSize) * zatoshisPerByte
}

// GetAddressFromPubKey generates a Zcash address from a hex-encoded public key
func GetAddressFromPubKey(hexPubKey string) (string, []byte, error) {
	pubKeyBytes, err := hex.DecodeString(hexPubKey)
	if err != nil {
		return "", nil, fmt.Errorf("invalid hex public key: %w", err)
	}

	if len(pubKeyBytes) != 33 {
		return "", nil, fmt.Errorf("invalid public key length: expected 33 bytes, got %d", len(pubKeyBytes))
	}

	addr, err := GetAddressFromPublicKey(pubKeyBytes)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get address: %w", err)
	}

	return addr, pubKeyBytes, nil
}
