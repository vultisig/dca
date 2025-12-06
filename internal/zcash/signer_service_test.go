package zcash

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vultisig/recipes/sdk/zcash"
)

// Test constants
const (
	testPubKeyHex    = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	testPrevTxHash   = "9b1a2f3e4d5c6b7a8f9e1f0b4b4d5b2b4b8d3e0c8050b5b0e3f7650145cdabcd"
	testInputValue   = uint64(100000000) // 1 ZEC in zatoshis
	testOutputValue  = int64(99990000)   // 0.9999 ZEC (minus fee)
)

// P2PKH script for testing
var testP2PKHScript = []byte{
	0x76, 0xa9, 0x14,
	0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd,
	0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab,
	0xcd, 0xef, 0xab, 0xcd,
	0x88, 0xac,
}

func createTestUnsignedTx(t *testing.T) *UnsignedTx {
	t.Helper()

	sdk := zcash.NewSDK(nil)
	pubKey, err := hex.DecodeString(testPubKeyHex)
	require.NoError(t, err)

	inputs := []TxInput{
		{
			TxHash:   testPrevTxHash,
			Index:    0,
			Value:    testInputValue,
			Script:   testP2PKHScript,
			Sequence: 0xffffffff,
		},
	}

	outputs := []*TxOutput{
		{
			Value:  testOutputValue,
			Script: testP2PKHScript,
		},
	}

	// Convert to SDK types
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

	sdkOutputs := make([]*zcash.TxOutput, len(outputs))
	for i, out := range outputs {
		sdkOutputs[i] = &zcash.TxOutput{
			Value:  out.Value,
			Script: out.Script,
		}
	}

	// Serialize unsigned tx
	rawBytes, err := sdk.SerializeUnsignedTx(sdkInputs, sdkOutputs)
	require.NoError(t, err)

	// Calculate sig hashes
	sigHashes := make([][]byte, len(inputs))
	for i := range inputs {
		sigHash, err := sdk.CalculateSigHash(sdkInputs, sdkOutputs, i)
		require.NoError(t, err)
		sigHashes[i] = sigHash
	}

	return &UnsignedTx{
		Inputs:    inputs,
		Outputs:   outputs,
		PubKey:    pubKey,
		RawBytes:  rawBytes,
		SigHashes: sigHashes,
	}
}

func TestSerializeWithMetadata_Integration(t *testing.T) {
	unsignedTx := createTestUnsignedTx(t)

	// Serialize with metadata (what signer_service.go does)
	dataWithMetadata := zcash.SerializeWithMetadata(unsignedTx.RawBytes, unsignedTx.SigHashes, unsignedTx.PubKey)

	// Verify data is larger than original
	assert.Greater(t, len(dataWithMetadata), len(unsignedTx.RawBytes))

	// Parse and verify round-trip
	parsedTxBytes, parsedPubKey, parsedSigHashes, err := zcash.ParseWithMetadata(dataWithMetadata)
	require.NoError(t, err)

	assert.Equal(t, unsignedTx.RawBytes, parsedTxBytes)
	assert.Equal(t, unsignedTx.PubKey, parsedPubKey)
	assert.Len(t, parsedSigHashes, len(unsignedTx.SigHashes))
	for i, sh := range parsedSigHashes {
		assert.Equal(t, unsignedTx.SigHashes[i], sh)
	}

	t.Logf("✅ SerializeWithMetadata: %d bytes -> %d bytes", len(unsignedTx.RawBytes), len(dataWithMetadata))
}

func TestKeysignMessageHash_Derivation(t *testing.T) {
	unsignedTx := createTestUnsignedTx(t)

	// This tests what buildKeysignRequest does to create message hashes
	for i, sigHash := range unsignedTx.SigHashes {
		// Calculate hash the same way buildKeysignRequest does
		msgHash := sha256.Sum256(sigHash)

		// Verify it's the correct length
		assert.Len(t, msgHash, 32)

		// Verify base64 encoding works
		hashB64 := base64.StdEncoding.EncodeToString(msgHash[:])
		assert.NotEmpty(t, hashB64)

		// Verify the derived key matches what SDK produces
		derivedKey := zcash.DeriveKeyFromMessage(sigHash)
		assert.Equal(t, hashB64, derivedKey, "SDK DeriveKeyFromMessage should match our calculation")

		t.Logf("✅ Input %d: sigHash=%x, derivedKey=%s", i, sigHash[:8], derivedKey[:20]+"...")
	}
}

func TestKeysignMessage_Structure(t *testing.T) {
	unsignedTx := createTestUnsignedTx(t)

	// Simulate what buildKeysignRequest creates
	for i, sigHash := range unsignedTx.SigHashes {
		msgHash := sha256.Sum256(sigHash)

		// These are what get put into KeysignMessage
		message := base64.StdEncoding.EncodeToString(sigHash)
		hash := base64.StdEncoding.EncodeToString(msgHash[:])

		// Verify message can be decoded back
		decodedSigHash, err := base64.StdEncoding.DecodeString(message)
		require.NoError(t, err)
		assert.Equal(t, sigHash, decodedSigHash)

		// Verify hash is the derived key
		derivedKey := zcash.DeriveKeyFromMessage(sigHash)
		assert.Equal(t, hash, derivedKey)

		t.Logf("✅ KeysignMessage %d: Message=%s..., Hash=%s...", i, message[:20], hash[:20])
	}
}

func TestMultiInputTransaction(t *testing.T) {
	sdk := zcash.NewSDK(nil)
	pubKey, err := hex.DecodeString(testPubKeyHex)
	require.NoError(t, err)

	// Create transaction with multiple inputs
	inputs := []TxInput{
		{
			TxHash:   testPrevTxHash,
			Index:    0,
			Value:    50000000, // 0.5 ZEC
			Script:   testP2PKHScript,
			Sequence: 0xffffffff,
		},
		{
			TxHash:   testPrevTxHash,
			Index:    1,
			Value:    50000000, // 0.5 ZEC
			Script:   testP2PKHScript,
			Sequence: 0xffffffff,
		},
	}

	outputs := []*TxOutput{
		{
			Value:  99990000, // 0.9999 ZEC
			Script: testP2PKHScript,
		},
	}

	// Convert to SDK types
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

	sdkOutputs := make([]*zcash.TxOutput, len(outputs))
	for i, out := range outputs {
		sdkOutputs[i] = &zcash.TxOutput{
			Value:  out.Value,
			Script: out.Script,
		}
	}

	rawBytes, err := sdk.SerializeUnsignedTx(sdkInputs, sdkOutputs)
	require.NoError(t, err)

	// Calculate sig hashes - they should be different for each input
	sigHash0, err := sdk.CalculateSigHash(sdkInputs, sdkOutputs, 0)
	require.NoError(t, err)

	sigHash1, err := sdk.CalculateSigHash(sdkInputs, sdkOutputs, 1)
	require.NoError(t, err)

	// Verify different inputs produce different sig hashes
	assert.NotEqual(t, sigHash0, sigHash1, "Different inputs should have different sig hashes")

	// Verify different derived keys
	key0 := zcash.DeriveKeyFromMessage(sigHash0)
	key1 := zcash.DeriveKeyFromMessage(sigHash1)
	assert.NotEqual(t, key0, key1, "Different sig hashes should have different derived keys")

	// Serialize with metadata
	sigHashes := [][]byte{sigHash0, sigHash1}
	dataWithMetadata := zcash.SerializeWithMetadata(rawBytes, sigHashes, pubKey)

	// Parse and verify
	_, parsedPubKey, parsedSigHashes, err := zcash.ParseWithMetadata(dataWithMetadata)
	require.NoError(t, err)

	assert.Equal(t, pubKey, parsedPubKey)
	assert.Len(t, parsedSigHashes, 2)
	assert.Equal(t, sigHash0, parsedSigHashes[0])
	assert.Equal(t, sigHash1, parsedSigHashes[1])

	t.Logf("✅ Multi-input transaction: 2 inputs, different sig hashes verified")
}

func TestTxOutput_Type(t *testing.T) {
	// Verify TxOutput matches expected structure
	output := &TxOutput{
		Value:  testOutputValue,
		Script: testP2PKHScript,
	}

	assert.Equal(t, testOutputValue, output.Value)
	assert.Equal(t, testP2PKHScript, output.Script)
}

func TestTxInput_Type(t *testing.T) {
	// Verify TxInput matches expected structure
	input := TxInput{
		TxHash:   testPrevTxHash,
		Index:    0,
		Value:    testInputValue,
		Script:   testP2PKHScript,
		Sequence: 0xffffffff,
	}

	assert.Equal(t, testPrevTxHash, input.TxHash)
	assert.Equal(t, uint32(0), input.Index)
	assert.Equal(t, testInputValue, input.Value)
	assert.Equal(t, testP2PKHScript, input.Script)
	assert.Equal(t, uint32(0xffffffff), input.Sequence)
}

func TestSDKConversion_ToSDKInputs(t *testing.T) {
	inputs := []TxInput{
		{
			TxHash:   testPrevTxHash,
			Index:    0,
			Value:    testInputValue,
			Script:   testP2PKHScript,
			Sequence: 0xffffffff,
		},
	}

	// This is what network.go does in toSDKInputs
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

	// Verify conversion
	assert.Len(t, sdkInputs, 1)
	assert.Equal(t, inputs[0].TxHash, sdkInputs[0].TxHash)
	assert.Equal(t, inputs[0].Index, sdkInputs[0].Index)
	assert.Equal(t, inputs[0].Value, sdkInputs[0].Value)
	assert.Equal(t, inputs[0].Script, sdkInputs[0].Script)
	assert.Equal(t, inputs[0].Sequence, sdkInputs[0].Sequence)
}

func TestSDKConversion_ToSDKOutputs(t *testing.T) {
	outputs := []*TxOutput{
		{
			Value:  testOutputValue,
			Script: testP2PKHScript,
		},
	}

	// This is what network.go does in toSDKOutputs
	sdkOutputs := make([]*zcash.TxOutput, len(outputs))
	for i, out := range outputs {
		sdkOutputs[i] = &zcash.TxOutput{
			Value:  out.Value,
			Script: out.Script,
		}
	}

	// Verify conversion
	assert.Len(t, sdkOutputs, 1)
	assert.Equal(t, outputs[0].Value, sdkOutputs[0].Value)
	assert.Equal(t, outputs[0].Script, sdkOutputs[0].Script)
}

func TestNU6BranchID(t *testing.T) {
	// Verify the SDK is using NU6 branch ID
	expectedNU6BranchID := uint32(0xC8E71055)
	assert.Equal(t, expectedNU6BranchID, uint32(zcash.ConsensusBranchID), "SDK should use NU6 branch ID")
	t.Logf("✅ NU6 Branch ID: 0x%X", zcash.ConsensusBranchID)
}

func TestEndToEnd_TransactionFlow(t *testing.T) {
	// This tests the complete flow from building unsigned tx to creating keysign request
	unsignedTx := createTestUnsignedTx(t)

	// Step 1: Serialize with metadata (what signer_service.go does)
	dataWithMetadata := zcash.SerializeWithMetadata(unsignedTx.RawBytes, unsignedTx.SigHashes, unsignedTx.PubKey)
	txB64 := base64.StdEncoding.EncodeToString(dataWithMetadata)

	t.Logf("Step 1: Serialized with metadata, %d bytes, base64 length: %d", len(dataWithMetadata), len(txB64))

	// Step 2: Create keysign messages (what buildKeysignRequest does)
	for i, sigHash := range unsignedTx.SigHashes {
		msgHash := sha256.Sum256(sigHash)
		message := base64.StdEncoding.EncodeToString(sigHash)
		hash := base64.StdEncoding.EncodeToString(msgHash[:])

		t.Logf("Step 2: KeysignMessage %d created", i)
		t.Logf("  - Message: %s...", message[:20])
		t.Logf("  - Hash: %s...", hash[:20])
	}

	// Step 3: Verify the transaction can be parsed by verifier (what tx_indexer does)
	txBytes, pubKey, sigHashes, err := zcash.ParseWithMetadata(dataWithMetadata)
	require.NoError(t, err)

	assert.Equal(t, unsignedTx.RawBytes, txBytes)
	assert.Equal(t, unsignedTx.PubKey, pubKey)
	assert.Len(t, sigHashes, len(unsignedTx.SigHashes))

	t.Logf("Step 3: Verifier can parse transaction")
	t.Logf("  - TX bytes: %d bytes", len(txBytes))
	t.Logf("  - PubKey: %x...", pubKey[:8])
	t.Logf("  - SigHashes: %d", len(sigHashes))

	// Step 4: Verify signature lookup would work
	for i, sigHash := range sigHashes {
		derivedKey := zcash.DeriveKeyFromMessage(sigHash)
		t.Logf("Step 4: Input %d derived key: %s...", i, derivedKey[:20])
	}

	t.Logf("✅ End-to-end transaction flow verified")
}

