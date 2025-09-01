package btc

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/vultisig/dca/internal/blockchair"
	"github.com/vultisig/vultisig-go/common"
)

type Network struct {
	rpc  *rpcclient.Client
	utxo *blockchair.Client
	fee  feeProvider
	swap *SwapService
}

func NewNetwork(rpc *rpcclient.Client, fee feeProvider, swap *SwapService) *Network {
	return &Network{
		rpc:  rpc,
		fee:  fee,
		swap: swap,
	}
}

func (n *Network) Swap(ctx context.Context, from From, to To) (*chainhash.Hash, error) {
	if to.Chain == common.Bitcoin {
		return nil, errors.New("can't swap btc to btc")
	}

	changeOutputIndex, _, outputs, err := n.swap.FindBestAmountOut(ctx, from, to)
	if err != nil {
		return nil, fmt.Errorf("find best amount out: %w", err)
	}

	msgTx, err := n.buildTx(ctx, from, outputs, changeOutputIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to build tx: %w", err)
	}

	tx, err := toPsbt(msgTx)
	if err != nil {
		return nil, fmt.Errorf("failed to convert tx to psbt: %w", err)
	}

	err = n.sendWithSdk(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("failed to send tx: %w", err)
	}
	return nil, nil
}

func (n *Network) sendWithSdk(ctx context.Context, tx *psbt.Packet) error {
	// todo implement
	return nil
}

func (n *Network) buildTx(
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

	tx := &wire.MsgTx{}
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

				prev, er := n.rpc.GetRawTransaction(txHash)
				if er != nil {
					return nil, fmt.Errorf("failed to get utxo tx: %w", er)
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
				if prev.MsgTx().HasWitness() {
					txIn.Witness = prev.MsgTx().TxIn[u.Index].Witness
				} else {
					txIn.SignatureScript = prev.MsgTx().TxIn[u.Index].SignatureScript
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

func toPsbt(tx *wire.MsgTx) (*psbt.Packet, error) {
	packet, err := psbt.NewFromUnsignedTx(tx.Copy())
	if err != nil {
		return nil, fmt.Errorf("failed to create PSBT: %w", err)
	}
	return packet, nil
}

func calcSizeBytes(tx *wire.MsgTx) int {
	// todo : add size of signatures
	return tx.SerializeSize()
}
