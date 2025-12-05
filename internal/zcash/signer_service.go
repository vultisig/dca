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
	"golang.org/x/crypto/blake2b"
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
// Uses Zcash v4 (Sapling) format for compatibility with recipes engine
func (s *SignerService) applySignatures(unsignedTx *UnsignedTx, signatures map[string]tss.KeysignResponse) ([]byte, error) {
	var buf bytes.Buffer

	// Zcash v4 transaction format (Sapling)
	// Version (4 bytes, little-endian) - version 4 with overwintered flag
	version := uint32(0x80000004)
	_ = binary.Write(&buf, binary.LittleEndian, version)

	// Version group ID (4 bytes, little-endian) - Sapling
	versionGroupID := uint32(0x892F2085)
	_ = binary.Write(&buf, binary.LittleEndian, versionGroupID)

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
		_ = binary.Write(&buf, binary.LittleEndian, input.Index)

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
		_ = binary.Write(&buf, binary.LittleEndian, uint32(0xffffffff))
	}

	// Transparent outputs count
	writeCompactSize(&buf, uint64(len(unsignedTx.Outputs)))

	// Transparent outputs
	for _, output := range unsignedTx.Outputs {
		_ = binary.Write(&buf, binary.LittleEndian, uint64(output.Value))
		writeCompactSize(&buf, uint64(len(output.Script)))
		buf.Write(output.Script)
	}

	// Lock time (4 bytes, little-endian)
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))

	// Expiry height (4 bytes, little-endian)
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))

	// Value balance (8 bytes, little-endian) - 0 for transparent-only
	_ = binary.Write(&buf, binary.LittleEndian, int64(0))

	// Shielded spends count - 0
	buf.WriteByte(0x00)

	// Shielded outputs count - 0
	buf.WriteByte(0x00)

	// JoinSplits count - 0 (for Sapling v4)
	buf.WriteByte(0x00)

	return buf.Bytes(), nil
}

// Sapling consensus branch ID for signature hash personalization
const saplingBranchID = 0x76B809BB

// CalculateSigHash computes the signature hash for a Zcash transparent input
// This uses the ZIP-243 signature hash algorithm for v4 (Sapling) transactions
func CalculateSigHash(inputs []TxInput, outputs []*TxOutput, inputIndex int) ([]byte, error) {
	// ZIP-243 signature hash for Sapling (v4) transactions
	// Uses BLAKE2b-256 with personalization "ZcashSigHash" + branch ID

	var preimage bytes.Buffer

	// 1. nVersion | nVersionGroupId (header)
	_ = binary.Write(&preimage, binary.LittleEndian, uint32(0x80000004)) // v4 with overwintered
	_ = binary.Write(&preimage, binary.LittleEndian, uint32(0x892F2085)) // Sapling version group

	// 2. hashPrevouts - BLAKE2b-256 of all prevouts
	hashPrevouts := calcHashPrevouts(inputs)
	preimage.Write(hashPrevouts)

	// 3. hashSequence - BLAKE2b-256 of all sequences
	hashSequence := calcHashSequence(inputs)
	preimage.Write(hashSequence)

	// 4. hashOutputs - BLAKE2b-256 of all outputs
	hashOutputs := calcHashOutputs(outputs)
	preimage.Write(hashOutputs)

	// 5. hashJoinSplits - 32 zero bytes (no joinsplits)
	preimage.Write(make([]byte, 32))

	// 6. hashShieldedSpends - 32 zero bytes (no shielded spends)
	preimage.Write(make([]byte, 32))

	// 7. hashShieldedOutputs - 32 zero bytes (no shielded outputs)
	preimage.Write(make([]byte, 32))

	// 8. nLockTime
	_ = binary.Write(&preimage, binary.LittleEndian, uint32(0))

	// 9. nExpiryHeight
	_ = binary.Write(&preimage, binary.LittleEndian, uint32(0))

	// 10. valueBalance (8 bytes) - 0 for transparent-only
	_ = binary.Write(&preimage, binary.LittleEndian, int64(0))

	// 11. nHashType
	_ = binary.Write(&preimage, binary.LittleEndian, uint32(1)) // SIGHASH_ALL

	// For SIGHASH_ALL, include the input being signed
	if inputIndex >= 0 && inputIndex < len(inputs) {
		input := inputs[inputIndex]

		// prevout (txid + index)
		txHashBytes, _ := hex.DecodeString(input.TxHash)
		// Reverse for little-endian
		for j := len(txHashBytes) - 1; j >= 0; j-- {
			preimage.WriteByte(txHashBytes[j])
		}
		_ = binary.Write(&preimage, binary.LittleEndian, input.Index)

		// scriptCode (with length prefix)
		writeCompactSize(&preimage, uint64(len(input.Script)))
		preimage.Write(input.Script)

		// amount (value of the input)
		_ = binary.Write(&preimage, binary.LittleEndian, input.Value)

		// nSequence
		_ = binary.Write(&preimage, binary.LittleEndian, uint32(0xffffffff))
	}

	// Final hash using BLAKE2b-256 with personalization
	return blake2bSigHash(preimage.Bytes())
}

// blake2bSigHash computes BLAKE2b-256 with Zcash signature hash personalization
func blake2bSigHash(data []byte) ([]byte, error) {
	// Personalization: "ZcashSigHash" (12 bytes) + branch ID (4 bytes, little-endian)
	personalization := make([]byte, 16)
	copy(personalization, "ZcashSigHash")
	binary.LittleEndian.PutUint32(personalization[12:], saplingBranchID)

	h, err := blake2b.New256(personalization)
	if err != nil {
		return nil, fmt.Errorf("failed to create BLAKE2b hasher: %w", err)
	}
	h.Write(data)
	return h.Sum(nil), nil
}

// calcHashPrevouts computes BLAKE2b-256 of all input prevouts
func calcHashPrevouts(inputs []TxInput) []byte {
	var buf bytes.Buffer
	for _, input := range inputs {
		txHashBytes, _ := hex.DecodeString(input.TxHash)
		// Reverse for little-endian
		for j := len(txHashBytes) - 1; j >= 0; j-- {
			buf.WriteByte(txHashBytes[j])
		}
		_ = binary.Write(&buf, binary.LittleEndian, input.Index)
	}

	personalization := make([]byte, 16)
	copy(personalization, "ZcashPrevoutHash")
	h, _ := blake2b.New256(personalization)
	h.Write(buf.Bytes())
	return h.Sum(nil)
}

// calcHashSequence computes BLAKE2b-256 of all input sequences
func calcHashSequence(inputs []TxInput) []byte {
	var buf bytes.Buffer
	for range inputs {
		_ = binary.Write(&buf, binary.LittleEndian, uint32(0xffffffff))
	}

	personalization := make([]byte, 16)
	copy(personalization, "ZcashSequencHash")
	h, _ := blake2b.New256(personalization)
	h.Write(buf.Bytes())
	return h.Sum(nil)
}

// calcHashOutputs computes BLAKE2b-256 of all outputs
func calcHashOutputs(outputs []*TxOutput) []byte {
	var buf bytes.Buffer
	for _, output := range outputs {
		_ = binary.Write(&buf, binary.LittleEndian, uint64(output.Value))
		writeCompactSize(&buf, uint64(len(output.Script)))
		buf.Write(output.Script)
	}

	personalization := make([]byte, 16)
	copy(personalization, "ZcashOutputsHash")
	h, _ := blake2b.New256(personalization)
	h.Write(buf.Bytes())
	return h.Sum(nil)
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
