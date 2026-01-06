package dash

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"

	"github.com/vultisig/recipes/engine"
	btcsdk "github.com/vultisig/recipes/sdk/btc"
	vtypes "github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/common"

	"github.com/vultisig/dca/internal/blockchair"
)

// Network orchestrates Dash transaction operations
type Network struct {
	fee        FeeProvider
	swap       *SwapService
	send       *SendService
	signerSend *SignerService
	signerSwap *SignerService
	utxos      *blockchair.Client
}

// NewNetwork creates a new Dash Network
func NewNetwork(
	fee FeeProvider,
	swap *SwapService,
	send *SendService,
	signerSend *SignerService,
	signerSwap *SignerService,
	utxos *blockchair.Client,
) *Network {
	return &Network{
		fee:        fee,
		swap:       swap,
		send:       send,
		signerSend: signerSend,
		signerSwap: signerSwap,
		utxos:      utxos,
	}
}

// SendPayment sends DASH to a destination address
func (n *Network) SendPayment(
	ctx context.Context,
	policy vtypes.PluginPolicy,
	fromAddress btcutil.Address,
	toAddress string,
	amountDuffs uint64,
	pubKey []byte,
) (string, error) {
	from := From{
		Address: fromAddress,
		Amount:  amountDuffs,
		PubKey:  pubKey,
	}

	outputs, changeOutputIndex, err := n.send.BuildTransfer(toAddress, fromAddress, amountDuffs)
	if err != nil {
		return "", fmt.Errorf("dash: failed to build transfer outputs: %w", err)
	}

	psbtTx, err := n.buildPSBT(ctx, from, outputs, changeOutputIndex)
	if err != nil {
		return "", fmt.Errorf("dash: failed to build psbt: %w", err)
	}

	txHash, err := n.signAndBroadcast(ctx, policy, "send", psbtTx)
	if err != nil {
		return "", fmt.Errorf("dash: failed to send tx: %w", err)
	}

	return txHash, nil
}

// SwapAssets performs a swap from DASH to another asset via MayaChain
func (n *Network) SwapAssets(
	ctx context.Context,
	policy vtypes.PluginPolicy,
	from From,
	to To,
) (string, error) {
	if to.Chain == common.Dash && to.AssetID == "" {
		return "", errors.New("dash: can't swap DASH to DASH")
	}

	// FindBestAmountOut returns: (expectedAmountOut, outputs, changeOutputIndex, error)
	_, outputs, changeOutputIndex, err := n.swap.FindBestAmountOut(ctx, from, to)
	if err != nil {
		return "", fmt.Errorf("dash: failed to find best amount out: %w", err)
	}

	psbtTx, err := n.buildPSBT(ctx, from, outputs, changeOutputIndex)
	if err != nil {
		return "", fmt.Errorf("dash: failed to build psbt: %w", err)
	}

	txHash, err := n.signAndBroadcast(ctx, policy, "swap", psbtTx)
	if err != nil {
		return "", fmt.Errorf("dash: failed to send tx: %w", err)
	}

	return txHash, nil
}

// buildPSBT builds a PSBT with UTXO selection and change calculation
func (n *Network) buildPSBT(
	ctx context.Context,
	from From,
	outputs []*wire.TxOut,
	changeOutputIndex int,
) (*psbt.Packet, error) {
	satsPerByte, err := n.fee.SatsPerByte(ctx)
	if err != nil {
		return nil, fmt.Errorf("dash: failed to get sats per byte: %w", err)
	}

	// Fetch all UTXOs
	utxos, err := n.FetchUTXOs(ctx, from.Address.String())
	if err != nil {
		return nil, err
	}

	if len(utxos) == 0 {
		return nil, fmt.Errorf("dash: no UTXOs available for address %s", from.Address.String())
	}

	// Build using SDK with Dash-specific parameters
	// Dash dust limit is 546 duffs (same as Bitcoin)
	builder := btcsdk.NewBuilder(546)

	result, err := builder.Build(utxos, outputs, changeOutputIndex, satsPerByte, from.PubKey)
	if err != nil {
		return nil, fmt.Errorf("dash: failed to build tx: %w", err)
	}

	// Populate PSBT metadata (blockchair.Client implements btc.PrevTxFetcher)
	err = btcsdk.PopulatePSBTMetadata(result, n.utxos)
	if err != nil {
		return nil, fmt.Errorf("dash: failed to populate psbt metadata: %w", err)
	}

	return result.Packet, nil
}

// FetchUTXOs fetches all unspent outputs for an address and converts to SDK format.
func (n *Network) FetchUTXOs(ctx context.Context, address string) ([]btcsdk.UTXO, error) {
	blockchairUtxos, err := n.utxos.GetAllUnspent(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("dash: failed to get UTXOs: %w", err)
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

// signAndBroadcast signs and broadcasts the transaction
func (n *Network) signAndBroadcast(
	ctx context.Context,
	policy vtypes.PluginPolicy,
	op string,
	tx *psbt.Packet,
) (string, error) {
	var bufPsbt bytes.Buffer
	err := tx.Serialize(&bufPsbt)
	if err != nil {
		return "", fmt.Errorf("dash: failed to serialize psbt: %w", err)
	}

	var bufWireTx bytes.Buffer
	err = tx.UnsignedTx.Serialize(&bufWireTx)
	if err != nil {
		return "", fmt.Errorf("dash: failed to serialize tx.UnsignedTx: %w", err)
	}

	recipe, err := policy.GetRecipe()
	if err != nil {
		return "", fmt.Errorf("dash: failed to unpack recipe: %w", err)
	}

	eng, err := engine.NewEngine()
	if err != nil {
		return "", fmt.Errorf("dash: failed to create engine: %w", err)
	}
	_, err = eng.Evaluate(recipe, common.Dash, bufWireTx.Bytes())
	if err != nil {
		return "", fmt.Errorf("dash: failed to evaluate tx: %w", err)
	}

	var txHash string
	switch op {
	case "send":
		txHash, err = n.signerSend.SignAndBroadcast(ctx, policy, bufPsbt.Bytes())
		if err != nil {
			return "", fmt.Errorf("dash: failed to sign and broadcast: %w", err)
		}
	case "swap":
		txHash, err = n.signerSwap.SignAndBroadcast(ctx, policy, bufPsbt.Bytes())
		if err != nil {
			return "", fmt.Errorf("dash: failed to sign and broadcast: %w", err)
		}
	default:
		return "", fmt.Errorf("dash: no signer for operation %s", op)
	}

	return txHash, nil
}

// GetAddressFromPubKey generates a Dash address from a hex-encoded public key
func GetAddressFromPubKey(hexPubKey string) (string, []byte, error) {
	pubKeyBytes, err := hex.DecodeString(hexPubKey)
	if err != nil {
		return "", nil, fmt.Errorf("dash: invalid hex public key: %w", err)
	}

	if len(pubKeyBytes) != 33 {
		return "", nil, fmt.Errorf("dash: invalid public key length: expected 33 bytes, got %d", len(pubKeyBytes))
	}

	// Generate Dash P2PKH address from compressed public key
	addr, err := btcutil.NewAddressPubKey(pubKeyBytes, &DashMainNetParams)
	if err != nil {
		return "", nil, fmt.Errorf("dash: failed to create address from pubkey: %w", err)
	}

	// Get the P2PKH address string (starts with 'X')
	addressStr := addr.AddressPubKeyHash().EncodeAddress()

	return addressStr, pubKeyBytes, nil
}
