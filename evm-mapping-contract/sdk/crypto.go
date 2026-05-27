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
//
// CRIT #11: behavior is canonical-by-default on go-vsc-node post-fix —
// high-S sigs are normalized to low-S before recovery. Legacy contract
// imports `crypto.ecrecover` continue to work, now with stronger guards.
func Ecrecover(hash []byte, sig []byte) ([]byte, error) {
	hashHex := hex.EncodeToString(hash)
	sigHex := hex.EncodeToString(sig)
	result := cryptoEcrecover(&hashHex, &sigHex)
	if result == nil {
		return nil, nil
	}
	return hex.DecodeString(*result)
}

// EcrecoverStrict is the REJECT-on-high-S ecrecover binding. Use this for
// SYSTEM signature sites where malleable sigs must NEVER be accepted
// (e.g. vault TSS-sig verification inside HandleConfirmSpend).
// CRIT #11 site 4 — see runtime_imports.go for the host binding name.
func EcrecoverStrict(hash []byte, sig []byte) ([]byte, error) {
	hashHex := hex.EncodeToString(hash)
	sigHex := hex.EncodeToString(sig)
	result := cryptoEcrecoverStrict(&hashHex, &sigHex)
	if result == nil {
		return nil, nil
	}
	return hex.DecodeString(*result)
}

// EcrecoverCanonical is the NORMALIZE-to-low-S ecrecover binding. Use
// this for USER signature sites where legacy wallets may emit high-S
// (e.g. ETH deposit verify in proof.go).
// CRIT #11 site 4 — see runtime_imports.go for the host binding name.
func EcrecoverCanonical(hash []byte, sig []byte) ([]byte, error) {
	hashHex := hex.EncodeToString(hash)
	sigHex := hex.EncodeToString(sig)
	result := cryptoEcrecoverCanonical(&hashHex, &sigHex)
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
