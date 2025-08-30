package btc

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/vultisig/dca/internal/blockchair"
	"github.com/vultisig/dca/internal/status"
	"github.com/vultisig/vultisig-go/common"
	"golang.org/x/sync/errgroup"
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

	maxInputs, _, outputs, err := n.swap.FindBestAmountOut(ctx, from, to)
	if err != nil {
		return nil, fmt.Errorf("find best amount out: %w", err)
	}

	utxos, err := n.utxo.PickUnspent(ctx, from.Address.EncodeAddress(), from.Amount, maxInputs)
	if err != nil {
		return nil, fmt.Errorf("failed to pick unspent utxo: %w", err)
	}

	type utxoMeta struct {
		utxo blockchair.Utxo
		tx   *btcutil.Tx
	}

	eg := &errgroup.Group{}
	utxosFull := make([]utxoMeta, len(utxos))
	for _i, _utxo := range utxos {
		i := _i
		utxo := _utxo
		eg.Go(func() error {
			hash := &chainhash.Hash{}
			er := chainhash.Decode(hash, utxo.TransactionHash)
			if er != nil {
				return fmt.Errorf("failed to decode hash: %w", err)
			}

			tx, er := n.rpc.GetRawTransaction(hash)
			if er != nil {
				return fmt.Errorf("failed to get utxo tx: %w", err)
			}

			utxosFull[i] = utxoMeta{
				utxo: utxo,
				tx:   tx,
			}
			return nil
		})
	}
	err = eg.Wait()
	if err != nil {
		return nil, fmt.Errorf("failed to get utxos: %w", err)
	}
}
