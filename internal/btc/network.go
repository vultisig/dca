package btc

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/vultisig/dca/internal/blockchair"
	"github.com/vultisig/recipes/engine"
	vtypes "github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/common"
)

type Network struct {
	rpc    *rpcclient.Client
	utxo   *blockchair.Client
	fee    feeProvider
	swap   *SwapService
	signer *SignerService
}

func NewNetwork(
	rpc *rpcclient.Client,
	fee feeProvider,
	swap *SwapService,
	signer *SignerService,
	utxo *blockchair.Client,
) *Network {
	return &Network{
		rpc:    rpc,
		utxo:   utxo,
		fee:    fee,
		swap:   swap,
		signer: signer,
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

	msgTx, err := n.buildMsgTx(ctx, from, outputs, changeOutputIndex)
	if err != nil {
		return "", fmt.Errorf("failed to build tx: %w", err)
	}

	psbtTx, err := toPsbt(msgTx, from.PubKey.PubKey().SerializeCompressed())
	if err != nil {
		return "", fmt.Errorf("failed to convert tx to psbt: %w", err)
	}

	err = n.populatePsbtMeta(psbtTx)
	if err != nil {
		return "", fmt.Errorf("failed to populate psbt metadata: %w", err)
	}

	txHash, err := n.sendWithSdk(ctx, policy, psbtTx)
	if err != nil {
		return "", fmt.Errorf("failed to send tx: %w", err)
	}
	return txHash, nil
}

func (n *Network) sendWithSdk(ctx context.Context, policy vtypes.PluginPolicy, tx *psbt.Packet) (string, error) {
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

	txHash, err := n.signer.SignAndBroadcast(ctx, policy, bufPsbt.Bytes())
	if err != nil {
		return "", fmt.Errorf("failed to sign and broadcast: %w", err)
	}

	return txHash, nil
}

func (n *Network) populatePsbtMeta(tx *psbt.Packet) error {
	for i := range tx.Inputs {
		prevOutPoint := tx.UnsignedTx.TxIn[i].PreviousOutPoint

		prevTx, err := n.rpc.GetRawTransaction(&prevOutPoint.Hash)
		if err != nil {
			return fmt.Errorf("failed to get previous transaction %s: %w", prevOutPoint.Hash.String(), err)
		}

		if int(prevOutPoint.Index) >= len(prevTx.MsgTx().TxOut) {
			return fmt.Errorf(
				"invalid output index %d for transaction %s",
				prevOutPoint.Index,
				prevOutPoint.Hash.String(),
			)
		}

		prevOutput := prevTx.MsgTx().TxOut[prevOutPoint.Index]

		if isWitnessScript(prevOutput.PkScript) {
			tx.Inputs[i].WitnessUtxo = prevOutput
		} else {
			tx.Inputs[i].NonWitnessUtxo = prevTx.MsgTx()
		}
	}

	return nil
}

func isWitnessScript(script []byte) bool {
	return txscript.IsPayToWitnessPubKeyHash(script) ||
		txscript.IsPayToWitnessScriptHash(script) ||
		txscript.IsPayToTaproot(script)
}

func (n *Network) buildMsgTx(
	ctx context.Context,
	from From,
	outputs []*wire.TxOut,
	changeOutputIndex int,
) (*wire.MsgTx, error) {
	satsPerByte, err := n.fee.SatsPerByte(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get sats per byte: %w", err)
	}

	utxoCtx, utxoCtxCancel := context.WithCancel(ctx)
	defer utxoCtxCancel()
	utxoCh := n.utxo.GetUnspent(utxoCtx, from.Address.String())

	tx := wire.NewMsgTx(wire.TxVersion)
	for _, o := range outputs {
		tx.AddTxOut(o)
	}

	var totalInputsValue uint64
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

			slices.SortFunc(utxoBatch.Utxos, func(a, b blockchair.Utxo) int {
				return cmp.Compare(b.Value, a.Value)
			})

			for _, u := range utxoBatch.Utxos {
				txHash := &chainhash.Hash{}
				er := chainhash.Decode(txHash, u.TransactionHash)
				if er != nil {
					return nil, fmt.Errorf("failed to decode transaction hash: %w", er)
				}

				txIn := &wire.TxIn{
					PreviousOutPoint: wire.OutPoint{
						Hash:  *txHash,
						Index: u.Index,
					},
					Sequence:        wire.MaxTxInSequenceNum,
					Witness:         nil,
					SignatureScript: nil,
				}

				tx.AddTxIn(txIn)
				totalInputsValue += u.Value

				fee := uint64(calcSizeBytes(tx)) * satsPerByte
				if totalInputsValue > from.Amount+fee {
					tx.TxOut[changeOutputIndex].Value = int64(totalInputsValue - from.Amount - fee)

					utxoCtxCancel()
					_ = <-utxoCh
					return tx, nil
				}
			}
		}
	}
}

func toPsbt(tx *wire.MsgTx, publicKey []byte) (*psbt.Packet, error) {
	packet, err := psbt.NewFromUnsignedTx(tx.Copy())
	if err != nil {
		return nil, fmt.Errorf("failed to create PSBT: %w", err)
	}

	for i := range packet.Inputs {
		derivation := &psbt.Bip32Derivation{
			PubKey:    publicKey,
			Bip32Path: nil, // Can be empty
		}
		packet.Inputs[i].Bip32Derivation = []*psbt.Bip32Derivation{derivation}
	}

	return packet, nil
}

func calcSizeBytes(tx *wire.MsgTx) int {
	// Base transaction size without signatures
	baseSize := tx.SerializeSize()

	// Add estimated signature sizes for each input
	sigSize := 0
	for _, txIn := range tx.TxIn {
		if txIn.Witness != nil && len(txIn.Witness) > 0 {
			// Witness transaction (P2WPKH, P2WSH, P2TR, etc.)
			// P2WPKH: ~108 bytes witness (signature ~72 + pubkey ~33 + length bytes)
			// P2WSH: varies, but assume ~200 bytes for multi-sig
			// P2TR: ~65 bytes (schnorr signature ~64 + length byte)
			if len(txIn.Witness) == 2 {
				// P2WPKH: signature + pubkey
				sigSize += 108
			} else if len(txIn.Witness) == 1 {
				// P2TR: single schnorr signature
				sigSize += 65
			} else {
				// P2WSH or complex witness script, estimate conservatively
				sigSize += 200
			}
		} else {
			// Legacy transaction (P2PKH, P2SH)
			// P2PKH: ~107 bytes (signature ~72 + pubkey ~33 + opcodes ~2)
			// P2SH: varies, but assume ~150 bytes for multi-sig
			if txIn.SignatureScript != nil && len(txIn.SignatureScript) > 0 {
				// Use existing script size as base, but estimate if empty
				sigSize += len(txIn.SignatureScript)
			} else {
				// Estimate P2PKH signature size
				sigSize += 107
			}
		}
	}

	// For witness transactions, add a witness flag overhead (2 bytes)
	hasWitness := false
	for _, txIn := range tx.TxIn {
		if txIn.Witness != nil && len(txIn.Witness) > 0 {
			hasWitness = true
			break
		}
	}

	if hasWitness {
		// Witness transactions have additional overhead
		return baseSize + sigSize + 2
	}

	return baseSize + sigSize
}
