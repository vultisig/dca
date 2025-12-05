package zcash

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/vultisig/mobile-tss-lib/tss"
	"github.com/vultisig/verifier/plugin/keysign"
	"github.com/vultisig/verifier/plugin/tx_indexer"
	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/storage"
	"github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/common"
)

// SignerService handles Zcash transaction signing and broadcasting
type SignerService struct {
	client    TxBroadcaster
	signer    *keysign.Signer
	txIndexer *tx_indexer.Service
}

// NewSignerService creates a new Zcash signer service
func NewSignerService(
	client TxBroadcaster,
	signer *keysign.Signer,
	txIndexer *tx_indexer.Service,
) *SignerService {
	return &SignerService{
		client:    client,
		signer:    signer,
		txIndexer: txIndexer,
	}
}

// UnsignedTx represents an unsigned Zcash transaction with all necessary info for signing
type UnsignedTx struct {
	Inputs    []TxInput
	Outputs   []*TxOutput
	PubKey    []byte
	RawBytes  []byte
	SigHashes [][]byte // Pre-computed signature hashes for each input
}

// SignAndBroadcast signs the transaction and broadcasts it to the network
func (s *SignerService) SignAndBroadcast(
	ctx context.Context,
	policy types.PluginPolicy,
	unsignedTx *UnsignedTx,
) (string, error) {
	keysignRequest, err := s.buildKeysignRequest(ctx, policy, unsignedTx)
	if err != nil {
		return "", fmt.Errorf("failed to build keysign request: %w", err)
	}

	signatures, err := s.signer.Sign(ctx, keysignRequest)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	signedTx, err := s.applySignatures(unsignedTx, signatures)
	if err != nil {
		return "", fmt.Errorf("failed to apply signatures: %w", err)
	}

	txHash, err := s.client.BroadcastTransaction(signedTx)
	if err != nil {
		return "", fmt.Errorf("failed to broadcast transaction: %w", err)
	}

	return txHash, nil
}

func (s *SignerService) buildKeysignRequest(
	ctx context.Context,
	policy types.PluginPolicy,
	unsignedTx *UnsignedTx,
) (types.PluginKeysignRequest, error) {
	txB64 := base64.StdEncoding.EncodeToString(unsignedTx.RawBytes)

	txToTrack, err := s.txIndexer.CreateTx(ctx, storage.CreateTxDto{
		PluginID:      policy.PluginID,
		PolicyID:      policy.ID,
		ChainID:       common.Zcash,
		TokenID:       "",
		FromPublicKey: policy.PublicKey,
		ToPublicKey:   "",
		ProposedTxHex: txB64,
	})
	if err != nil {
		return types.PluginKeysignRequest{}, fmt.Errorf("failed to create tx: %w", err)
	}

	var msgs []types.KeysignMessage
	for i, sigHash := range unsignedTx.SigHashes {
		msgHash := sha256.Sum256(sigHash)
		msgs = append(msgs, types.KeysignMessage{
			TxIndexerID:  txToTrack.ID.String(),
			Message:      base64.StdEncoding.EncodeToString(sigHash),
			Hash:         base64.StdEncoding.EncodeToString(msgHash[:]),
			HashFunction: types.HashFunction_SHA256,
			Chain:        common.Zcash,
		})

		_ = i // avoid unused variable warning
	}

	return types.PluginKeysignRequest{
		KeysignRequest: types.KeysignRequest{
			PublicKey: policy.PublicKey,
			Messages:  msgs,
			PolicyID:  policy.ID,
			PluginID:  policy.PluginID.String(),
		},
		Transaction: txB64,
	}, nil
}

// applySignatures applies TSS signatures to create a signed transaction
func (s *SignerService) applySignatures(unsignedTx *UnsignedTx, signatures map[string]tss.KeysignResponse) ([]byte, error) {
	var buf bytes.Buffer

	// Zcash v5 transaction format
	// Version (4 bytes, little-endian) - version 5 with overwintered flag
	version := uint32(0x80000005)
	binary.Write(&buf, binary.LittleEndian, version)

	// Version group ID (4 bytes, little-endian) - NU5
	versionGroupID := uint32(0x26A7270A)
	binary.Write(&buf, binary.LittleEndian, versionGroupID)

	// Consensus branch ID (4 bytes, little-endian) - NU5
	branchID := uint32(0xC2D6D0B4)
	binary.Write(&buf, binary.LittleEndian, branchID)

	// Lock time (4 bytes, little-endian)
	binary.Write(&buf, binary.LittleEndian, uint32(0))

	// Expiry height (4 bytes, little-endian)
	binary.Write(&buf, binary.LittleEndian, uint32(0))

	// Transparent inputs count
	writeCompactSize(&buf, uint64(len(unsignedTx.Inputs)))

	// Transparent inputs with signatures
	for i, input := range unsignedTx.Inputs {
		// Previous output hash (32 bytes, reversed)
		txHashBytes, err := hex.DecodeString(input.TxHash)
		if err != nil {
			return nil, fmt.Errorf("invalid tx hash: %w", err)
		}
		for j := len(txHashBytes) - 1; j >= 0; j-- {
			buf.WriteByte(txHashBytes[j])
		}

		// Previous output index (4 bytes, little-endian)
		binary.Write(&buf, binary.LittleEndian, input.Index)

		// Get signature for this input
		sigHash := unsignedTx.SigHashes[i]
		derivedKey := deriveKeyFromMessage(sigHash)

		sig, exists := signatures[derivedKey]
		if !exists {
			return nil, fmt.Errorf("missing signature for input %d (key: %s)", i, derivedKey)
		}

		// Build scriptSig for P2PKH: <sig> <pubkey>
		derSig, err := hex.DecodeString(trim0x(sig.DerSignature))
		if err != nil {
			return nil, fmt.Errorf("failed to decode DER signature: %w", err)
		}

		// Append SIGHASH_ALL
		fullSig := append(derSig, 0x01)

		// scriptSig: <sig_length> <sig> <pubkey_length> <pubkey>
		scriptSig := make([]byte, 0, 2+len(fullSig)+len(unsignedTx.PubKey))
		scriptSig = append(scriptSig, byte(len(fullSig)))
		scriptSig = append(scriptSig, fullSig...)
		scriptSig = append(scriptSig, byte(len(unsignedTx.PubKey)))
		scriptSig = append(scriptSig, unsignedTx.PubKey...)

		// Script length
		writeCompactSize(&buf, uint64(len(scriptSig)))
		buf.Write(scriptSig)

		// Sequence (4 bytes)
		binary.Write(&buf, binary.LittleEndian, uint32(0xffffffff))
	}

	// Transparent outputs count
	writeCompactSize(&buf, uint64(len(unsignedTx.Outputs)))

	// Transparent outputs
	for _, output := range unsignedTx.Outputs {
		binary.Write(&buf, binary.LittleEndian, uint64(output.Value))
		writeCompactSize(&buf, uint64(len(output.Script)))
		buf.Write(output.Script)
	}

	// Sapling spends count - 0
	buf.WriteByte(0x00)

	// Sapling outputs count - 0
	buf.WriteByte(0x00)

	// Orchard actions count - 0
	buf.WriteByte(0x00)

	return buf.Bytes(), nil
}

// CalculateSigHash computes the signature hash for a Zcash transparent input
// This uses the ZIP-244 signature hash algorithm for v5 transactions
func CalculateSigHash(inputs []TxInput, outputs []*TxOutput, inputIndex int) ([]byte, error) {
	// For v5 transactions, we use ZIP-244 signature hash
	// Simplified implementation for transparent P2PKH inputs

	var preimage bytes.Buffer

	// 1. header_digest (32 bytes)
	headerDigest := calcHeaderDigest()
	preimage.Write(headerDigest)

	// 2. transparent_digest (32 bytes)
	transparentDigest := calcTransparentDigest(inputs, outputs, inputIndex)
	preimage.Write(transparentDigest)

	// 3. sapling_digest (32 bytes) - all zeros for transparent-only
	saplingDigest := make([]byte, 32)
	preimage.Write(saplingDigest)

	// 4. orchard_digest (32 bytes) - all zeros for transparent-only
	orchardDigest := make([]byte, 32)
	preimage.Write(orchardDigest)

	// Double SHA256 for final signature hash
	hash1 := sha256.Sum256(preimage.Bytes())
	hash2 := sha256.Sum256(hash1[:])

	return hash2[:], nil
}

// calcHeaderDigest computes the header portion of the signature hash
func calcHeaderDigest() []byte {
	var buf bytes.Buffer

	// Version
	binary.Write(&buf, binary.LittleEndian, uint32(0x80000005))
	// Version group ID
	binary.Write(&buf, binary.LittleEndian, uint32(0x26A7270A))
	// Consensus branch ID
	binary.Write(&buf, binary.LittleEndian, uint32(0xC2D6D0B4))
	// Lock time
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	// Expiry height
	binary.Write(&buf, binary.LittleEndian, uint32(0))

	hash := sha256.Sum256(buf.Bytes())
	return hash[:]
}

// calcTransparentDigest computes the transparent portion of the signature hash
func calcTransparentDigest(inputs []TxInput, outputs []*TxOutput, inputIndex int) []byte {
	var buf bytes.Buffer

	// Hash of all input prevouts
	var prevoutsHash bytes.Buffer
	for _, input := range inputs {
		txHashBytes, _ := hex.DecodeString(input.TxHash)
		// Reverse for little-endian
		for j := len(txHashBytes) - 1; j >= 0; j-- {
			prevoutsHash.WriteByte(txHashBytes[j])
		}
		binary.Write(&prevoutsHash, binary.LittleEndian, input.Index)
	}
	prevoutsDigest := sha256.Sum256(prevoutsHash.Bytes())
	buf.Write(prevoutsDigest[:])

	// Hash of all input amounts
	var amountsHash bytes.Buffer
	for _, input := range inputs {
		binary.Write(&amountsHash, binary.LittleEndian, input.Value)
	}
	amountsDigest := sha256.Sum256(amountsHash.Bytes())
	buf.Write(amountsDigest[:])

	// Hash of all input scriptPubKeys
	var scriptsHash bytes.Buffer
	for _, input := range inputs {
		writeCompactSize(&scriptsHash, uint64(len(input.Script)))
		scriptsHash.Write(input.Script)
	}
	scriptsDigest := sha256.Sum256(scriptsHash.Bytes())
	buf.Write(scriptsDigest[:])

	// Hash of all sequences
	var sequencesHash bytes.Buffer
	for range inputs {
		binary.Write(&sequencesHash, binary.LittleEndian, uint32(0xffffffff))
	}
	sequencesDigest := sha256.Sum256(sequencesHash.Bytes())
	buf.Write(sequencesDigest[:])

	// Hash of all outputs
	var outputsHash bytes.Buffer
	for _, output := range outputs {
		binary.Write(&outputsHash, binary.LittleEndian, uint64(output.Value))
		writeCompactSize(&outputsHash, uint64(len(output.Script)))
		outputsHash.Write(output.Script)
	}
	outputsDigest := sha256.Sum256(outputsHash.Bytes())
	buf.Write(outputsDigest[:])

	// Input being signed
	if inputIndex >= 0 && inputIndex < len(inputs) {
		input := inputs[inputIndex]
		txHashBytes, _ := hex.DecodeString(input.TxHash)
		for j := len(txHashBytes) - 1; j >= 0; j-- {
			buf.WriteByte(txHashBytes[j])
		}
		binary.Write(&buf, binary.LittleEndian, input.Index)
		binary.Write(&buf, binary.LittleEndian, input.Value)
		writeCompactSize(&buf, uint64(len(input.Script)))
		buf.Write(input.Script)
		binary.Write(&buf, binary.LittleEndian, uint32(0xffffffff))
	}

	// Sighash type
	binary.Write(&buf, binary.LittleEndian, uint32(1)) // SIGHASH_ALL

	hash := sha256.Sum256(buf.Bytes())
	return hash[:]
}

// deriveKeyFromMessage derives a key from a message hash
func deriveKeyFromMessage(messageHash []byte) string {
	hash := sha256.Sum256(messageHash)
	return base64.StdEncoding.EncodeToString(hash[:])
}

func trim0x(s string) string {
	if len(s) >= 2 && (s[0:2] == "0x" || s[0:2] == "0X") {
		return s[2:]
	}
	return s
}
