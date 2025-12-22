package btc

import (
	"bytes"
	"context"
	"errors"
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

type Network struct {
	utxo       *blockchair.Client
	fee        feeProvider
	swap       *SwapService
	send       *SendService
	signerSend *SignerService
	signerSwap *SignerService
}

func NewNetwork(
	fee feeProvider,
	swap *SwapService,
	send *SendService,
	signerSend *SignerService,
	signerSwap *SignerService,
	utxo *blockchair.Client,
) *Network {
	return &Network{
		utxo:       utxo,
		fee:        fee,
		swap:       swap,
		send:       send,
		signerSend: signerSend,
		signerSwap: signerSwap,
	}
}

func (n *Network) Swap(ctx context.Context, policy vtypes.PluginPolicy, from From, to To) (string, error) {
	if to.Chain == common.Bitcoin {
		return "", errors.New("can't swap btc to btc")
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

func (n *Network) Send(
	ctx context.Context,
	policy vtypes.PluginPolicy,
	from From,
	toAddresses []string,
	amounts []uint64,
) (string, error) {
	outputs, changeOutputIndex, err := n.send.BuildTransfer(toAddresses, amounts, from.Address)
	if err != nil {
		return "", fmt.Errorf("failed to build transfer outputs: %w", err)
	}

	psbtTx, err := n.buildPSBT(ctx, from, outputs, changeOutputIndex)
	if err != nil {
		return "", fmt.Errorf("failed to build psbt: %w", err)
	}

	txHash, err := n.sendWithSdk(ctx, policy, types.OperationSend, psbtTx)
	if err != nil {
		return "", fmt.Errorf("failed to send tx: %w", err)
	}
	return txHash, nil
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
	blockchairUtxos, err := n.utxo.GetAllUnspent(ctx, from.Address.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get utxos: %w", err)
	}

	// Convert to SDK UTXO format
	utxos := make([]btcsdk.UTXO, len(blockchairUtxos))
	for i, u := range blockchairUtxos {
		utxos[i] = btcsdk.UTXO{
			TxHash: u.TransactionHash,
			Index:  u.Index,
			Value:  u.Value,
		}
	}

	// Build using SDK
	builder := btcsdk.Mainnet()
	pubKey := from.PubKey.PubKey().SerializeCompressed()

	result, err := builder.Build(utxos, outputs, changeOutputIndex, satsPerByte, pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to build tx: %w", err)
	}

	// Populate PSBT metadata
	err = btcsdk.PopulatePSBTMetadata(result, n.utxo)
	if err != nil {
		return nil, fmt.Errorf("failed to populate psbt metadata: %w", err)
	}

	return result.Packet, nil
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
	_, err = eng.Evaluate(recipe, common.Bitcoin, bufWireTx.Bytes())
	if err != nil {
		return "", fmt.Errorf("failed to evaluate tx: %w", err)
	}

	var txHash string
	switch op {
	case types.OperationSend:
		txHash, err = n.signerSend.SignAndBroadcast(ctx, policy, bufPsbt.Bytes())
		if err != nil {
			return "", fmt.Errorf("failed to sign and broadcast: %w", err)
		}
	case types.OperationSwap:
		txHash, err = n.signerSwap.SignAndBroadcast(ctx, policy, bufPsbt.Bytes())
		if err != nil {
			return "", fmt.Errorf("failed to sign and broadcast: %w", err)
		}
	default:
		return "", fmt.Errorf("no signer for operation %s", op)
	}

	return txHash, nil
}
