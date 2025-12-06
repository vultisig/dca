package zcash

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // RIPEMD160 required for Hash160 (Bitcoin/Zcash address standard)
)

// Zcash mainnet address prefixes (2 bytes)
var (
	// ZcashMainNetP2PKH is the prefix for transparent P2PKH addresses (t1...)
	ZcashMainNetP2PKH = []byte{0x1C, 0xB8}
	// ZcashMainNetP2SH is the prefix for P2SH addresses (t3...)
	ZcashMainNetP2SH = []byte{0x1C, 0xBD}
)

// Base58 alphabet used by Zcash (same as Bitcoin)
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// Hash160 computes RIPEMD160(SHA256(data))
func Hash160(data []byte) []byte {
	sha := sha256.Sum256(data)
	r := ripemd160.New()
	r.Write(sha[:])
	return r.Sum(nil)
}

// Base58CheckDecode decodes a base58check encoded string
func Base58CheckDecode(s string) ([]byte, error) {
	decoded := base58Decode(s)
	if len(decoded) < 6 {
		return nil, errors.New("decoded string too short")
	}

	// Verify checksum
	payload := decoded[:len(decoded)-4]
	checksum := decoded[len(decoded)-4:]

	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])

	if second[0] != checksum[0] || second[1] != checksum[1] ||
		second[2] != checksum[2] || second[3] != checksum[3] {
		return nil, errors.New("checksum mismatch")
	}

	return payload, nil
}

// base58Decode decodes a base58 string to bytes
func base58Decode(s string) []byte {
	num := big.NewInt(0)
	base := big.NewInt(58)

	for _, c := range s {
		charIndex := -1
		for i, ac := range base58Alphabet {
			if c == ac {
				charIndex = i
				break
			}
		}
		if charIndex == -1 {
			return nil
		}
		num.Mul(num, base)
		num.Add(num, big.NewInt(int64(charIndex)))
	}

	result := num.Bytes()

	// Count leading 1s (zeros in the decoded result)
	leadingZeros := 0
	for _, c := range s {
		if c != '1' {
			break
		}
		leadingZeros++
	}

	// Prepend zeros
	final := make([]byte, leadingZeros+len(result))
	copy(final[leadingZeros:], result)

	return final
}

// DecodeZcashAddress decodes a Zcash transparent address and returns the pubkey hash
func DecodeZcashAddress(address string) ([]byte, bool, error) {
	decoded, err := Base58CheckDecode(address)
	if err != nil {
		return nil, false, fmt.Errorf("failed to decode address: %w", err)
	}

	// Zcash uses 2-byte prefix + 20-byte hash
	if len(decoded) != 22 {
		return nil, false, fmt.Errorf("invalid address length: expected 22 bytes, got %d", len(decoded))
	}

	prefix := decoded[:2]
	hash := decoded[2:]

	isP2PKH := prefix[0] == ZcashMainNetP2PKH[0] && prefix[1] == ZcashMainNetP2PKH[1]
	isP2SH := prefix[0] == ZcashMainNetP2SH[0] && prefix[1] == ZcashMainNetP2SH[1]

	if !isP2PKH && !isP2SH {
		return nil, false, fmt.Errorf("unknown address prefix: %x", prefix)
	}

	return hash, isP2PKH, nil
}

// PayToAddrScript creates a P2PKH or P2SH script from a Zcash address
func PayToAddrScript(address string) ([]byte, error) {
	hash, isP2PKH, err := DecodeZcashAddress(address)
	if err != nil {
		return nil, fmt.Errorf("failed to decode address: %w", err)
	}

	if isP2PKH {
		// P2PKH script: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
		script := make([]byte, 25)
		script[0] = 0x76 // OP_DUP
		script[1] = 0xa9 // OP_HASH160
		script[2] = 0x14 // Push 20 bytes
		copy(script[3:23], hash)
		script[23] = 0x88 // OP_EQUALVERIFY
		script[24] = 0xac // OP_CHECKSIG
		return script, nil
	}

	// P2SH script: OP_HASH160 <20 bytes> OP_EQUAL
	script := make([]byte, 23)
	script[0] = 0xa9 // OP_HASH160
	script[1] = 0x14 // Push 20 bytes
	copy(script[2:22], hash)
	script[22] = 0x87 // OP_EQUAL
	return script, nil
}

// CreateMemoScript creates an OP_RETURN script with the given memo
func CreateMemoScript(memo string) ([]byte, error) {
	data := []byte(memo)
	if len(data) > 80 {
		return nil, fmt.Errorf("memo too long: %d bytes, max 80", len(data))
	}

	// OP_RETURN <push data>
	script := make([]byte, 0, 2+len(data))
	script = append(script, 0x6a) // OP_RETURN

	if len(data) < 76 {
		script = append(script, byte(len(data)))
	} else {
		script = append(script, 0x4c) // OP_PUSHDATA1
		script = append(script, byte(len(data)))
	}

	script = append(script, data...)
	return script, nil
}

// PubKeyHashFromPublicKey computes the pubkey hash from a compressed public key
func PubKeyHashFromPublicKey(pubKey []byte) []byte {
	return Hash160(pubKey)
}

// IsP2PKHScript checks if a script is a P2PKH script
func IsP2PKHScript(script []byte) bool {
	return len(script) == 25 &&
		script[0] == 0x76 &&
		script[1] == 0xa9 &&
		script[2] == 0x14 &&
		script[23] == 0x88 &&
		script[24] == 0xac
}

// GetAddressFromPublicKey generates a Zcash t1... address from a public key
func GetAddressFromPublicKey(pubKey []byte) (string, error) {
	if len(pubKey) != 33 {
		return "", fmt.Errorf("invalid public key length: expected 33 bytes, got %d", len(pubKey))
	}

	hash := Hash160(pubKey)
	return encodeZcashAddress(ZcashMainNetP2PKH, hash), nil
}

// encodeZcashAddress encodes a hash with prefix to a base58check address
func encodeZcashAddress(prefix []byte, hash []byte) string {
	data := make([]byte, len(prefix)+len(hash))
	copy(data, prefix)
	copy(data[len(prefix):], hash)
	return base58CheckEncode(data)
}

// base58CheckEncode encodes data to base58check format
func base58CheckEncode(data []byte) string {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	checksum := second[:4]

	payload := make([]byte, len(data)+4)
	copy(payload, data)
	copy(payload[len(data):], checksum)

	return base58Encode(payload)
}

// base58Encode encodes bytes to base58
func base58Encode(data []byte) string {
	var zeros int
	for _, b := range data {
		if b != 0 {
			break
		}
		zeros++
	}

	num := new(big.Int).SetBytes(data)
	base := big.NewInt(58)
	mod := new(big.Int)

	var result []byte
	for num.Sign() > 0 {
		num.DivMod(num, base, mod)
		result = append([]byte{base58Alphabet[mod.Int64()]}, result...)
	}

	for i := 0; i < zeros; i++ {
		result = append([]byte{'1'}, result...)
	}

	return string(result)
}

// ValidateAddress validates a Zcash transparent address
func ValidateAddress(address string) error {
	if len(address) < 2 {
		return errors.New("address too short")
	}

	// Transparent addresses start with 't1' (P2PKH) or 't3' (P2SH)
	if address[0] != 't' {
		return errors.New("invalid address: must start with 't'")
	}

	_, _, err := DecodeZcashAddress(address)
	return err
}

// HexToPubKeyBytes converts a hex-encoded public key to bytes
func HexToPubKeyBytes(hexPubKey string) ([]byte, error) {
	pubKeyBytes, err := hex.DecodeString(hexPubKey)
	if err != nil {
		return nil, fmt.Errorf("invalid hex public key: %w", err)
	}

	if len(pubKeyBytes) != 33 {
		return nil, fmt.Errorf("invalid public key length: expected 33 bytes, got %d", len(pubKeyBytes))
	}

	return pubKeyBytes, nil
}
