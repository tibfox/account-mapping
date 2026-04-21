package sdk

import "encoding/hex"

// Keccak256 computes the Keccak-256 hash via the host runtime.
// Input and output are raw byte slices (not hex-encoded).
func Keccak256(data []byte) []byte {
	input := hex.EncodeToString(data)
	result := cryptoKeccak256(&input)
	if result == nil {
		return nil
	}
	out, _ := hex.DecodeString(*result)
	return out
}

// Ecrecover recovers the public key address from a hash and signature.
// hash must be 32 bytes, sig must be 65 bytes (r[32] + s[32] + v[1]).
// Returns the 20-byte Ethereum address.
func Ecrecover(hash []byte, sig []byte) ([]byte, error) {
	hashHex := hex.EncodeToString(hash)
	sigHex := hex.EncodeToString(sig)
	result := cryptoEcrecover(&hashHex, &sigHex)
	if result == nil {
		return nil, nil
	}
	return hex.DecodeString(*result)
}

// RlpDecode decodes RLP-encoded data via the host runtime.
// Returns the JSON string representation of decoded items.
func RlpDecode(data []byte) string {
	input := hex.EncodeToString(data)
	result := cryptoRlpDecode(&input)
	if result == nil {
		return ""
	}
	return *result
}
