//go:build !gc.custom

package sdk

import (
	"encoding/hex"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

//go:wasmimport sdk console.log
func log(s *string) *string { return nil }

func Log(s string) {
	log(&s)
}

// In-memory persistent state for non-wasm (test) builds. Production builds
// use the gc.custom variant in runtime_imports.go which delegates to host
// imports. Keeping a real store here lets unit tests in `contract/mapping`
// exercise stateful helpers (GetSupply/SetSupply, getGasReserve, GetBalance,
// etc.) end-to-end without standing up a full devnet.
var stubStateStore = map[string]string{}

// ResetStubState clears the in-memory store. Test-only helper.
func ResetStubState() {
	for k := range stubStateStore {
		delete(stubStateStore, k)
	}
	for k := range stubEphemStore {
		delete(stubEphemStore, k)
	}
	stubEnvJSON = `{"contract.id":"vsc1stub","tx.id":"","tx.index":0,"tx.op_index":0,"block.id":"","block.height":0,"block.timestamp":"","msg.sender":"hive:stubcaller","msg.caller":"hive:stubcaller","msg.payer":"hive:stubcaller","msg.required_auths":[],"msg.required_posting_auths":[],"sender":{},"intents":[]}`
	stubContractCallResponder = nil
	stubContractReadResponder = nil
}

func stateSetObject(key *string, value *string) *string {
	stubStateStore[*key] = *value
	return nil
}

func stateGetObject(key *string) *string {
	v, ok := stubStateStore[*key]
	if !ok {
		return nil
	}
	return &v
}

func stateDeleteObject(key *string) *string {
	delete(stubStateStore, *key)
	return nil
}

var stubEphemStore = map[string]string{}

func ephemStateSetObject(key *string, value *string) *string {
	stubEphemStore[*key] = *value
	return nil
}

func ephemStateGetObject(contractId *string, key *string) *string {
	v, ok := stubEphemStore[*key]
	if !ok {
		return nil
	}
	return &v
}

func ephemStateDeleteObject(key *string) *string {
	delete(stubEphemStore, *key)
	return nil
}

// stubEnvJSON is the JSON blob returned by `system.get_env` in stub mode.
// Tests can override via StubSetEnvJSON. A sensible default is populated so
// helpers that touch GetEnv (e.g. routeDeposit's swap branch) work out of
// the box without test boilerplate.
var stubEnvJSON = `{"contract.id":"vsc1stub","tx.id":"","tx.index":0,"tx.op_index":0,"block.id":"","block.height":0,"block.timestamp":"","msg.sender":"hive:stubcaller","msg.caller":"hive:stubcaller","msg.payer":"hive:stubcaller","msg.required_auths":[],"msg.required_posting_auths":[],"sender":{},"intents":[]}`

// StubSetEnvJSON installs the JSON blob `getEnv` should return. Test-only.
func StubSetEnvJSON(j string) { stubEnvJSON = j }

func getEnv(arg *string) *string {
	out := stubEnvJSON
	return &out
}

//go:wasmimport sdk system.get_env_key
func getEnvKey(arg *string) *string { return nil }

//go:wasmimport sdk system.verify_address
func verifyAddress(arg *string) *string { return nil }

//go:wasmimport sdk hive.get_balance
func getBalance(arg1 *string, arg2 *string) *string { return nil }

//go:wasmimport sdk hive.draw
func hiveDraw(arg1 *string, arg2 *string) *string { return nil }

//go:wasmimport sdk hive.draw_from
func hiveDrawFrom(arg1 *string, arg2 *string, arg3 *string) *string { return nil }

//go:wasmimport sdk hive.transfer
func hiveTransfer(arg1 *string, arg2 *string, arg3 *string) *string { return nil }

//go:wasmimport sdk hive.withdraw
func hiveWithdraw(arg1 *string, arg2 *string, arg3 *string) *string { return nil }

// stubContractReadResponder lets tests intercept contracts.read so external
// contract reads (e.g. blocklist.readState pulling from the ZK header
// verifier contract) can be mocked. Returning nil emulates "absent".
var stubContractReadResponder func(contractId, key string) *string

// StubSetContractReadResponder installs the contracts.read hook. Test-only.
func StubSetContractReadResponder(fn func(contractId, key string) *string) {
	stubContractReadResponder = fn
}

func contractRead(contractId *string, key *string) *string {
	if stubContractReadResponder != nil {
		return stubContractReadResponder(*contractId, *key)
	}
	return nil
}

// stubContractCallResponder lets tests intercept contracts.call. Returning
// nil emulates the host returning nil (call failed). Test-only.
var stubContractCallResponder func(contractId, method, payload string) *string

// StubSetContractCallResponder installs the contracts.call hook. Test-only.
func StubSetContractCallResponder(fn func(contractId, method, payload string) *string) {
	stubContractCallResponder = fn
}

func contractCall(contractId *string, method *string, payload *string, options *string) *string {
	if stubContractCallResponder != nil {
		return stubContractCallResponder(*contractId, *method, *payload)
	}
	return nil
}

//go:wasmimport sdk tss_v2.create_key
func tssCreateKey(keyId *string, algo *string, epochs *string) *string { return nil }

//go:wasmimport sdk tss_v2.renew_key
func tssRenewKey(keyId *string, epochs *string) *string { return nil }

//go:wasmimport sdk tss.sign_key
func tssSignKey(keyId *string, msgId *string) *string { return nil }

//go:wasmimport sdk tss.get_key
func tssGetKey(keyId *string) *string { return nil }

// var envMap = []string{
// 	"contract.id",
// 	"tx.origin",
// 	"tx.id",
// 	"tx.index",
// 	"tx.op_index",
// 	"block.id",
// 	"block.height",
// 	"block.timestamp",
// }

func cryptoKeccak256(hexData *string) *string {
	data, _ := hex.DecodeString(*hexData)
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	result := hex.EncodeToString(h.Sum(nil))
	return &result
}

func cryptoEcrecover(hashHex *string, sigHex *string) *string {
	hash, _ := hex.DecodeString(*hashHex)
	sig, _ := hex.DecodeString(*sigHex)
	if len(sig) != 65 {
		return nil
	}
	// Convert from r[32]+s[32]+v[1] to v[1]+r[32]+s[32] for RecoverCompact
	// go-ethereum format: v is 0 or 1. dcrd RecoverCompact: v is 27 or 28.
	compactSig := make([]byte, 65)
	compactSig[0] = sig[64] + 27 // convert 0/1 → 27/28 for RecoverCompact
	copy(compactSig[1:33], sig[0:32]) // r
	copy(compactSig[33:65], sig[32:64]) // s
	pubKey, _, err := ecdsa.RecoverCompact(compactSig, hash)
	if err != nil {
		return nil
	}
	uncompressed := pubKey.SerializeUncompressed()
	h := sha3.NewLegacyKeccak256()
	h.Write(uncompressed[1:])
	addr := hex.EncodeToString(h.Sum(nil)[12:])
	return &addr
}

// CRIT #11 site 4 — stub-mode shims for the explicit-name host bindings.
// Behavior equivalence with the wasmimport names is not required for
// unit-test stubs; mirror the same recovery as cryptoEcrecover.
func cryptoEcrecoverStrict(hashHex *string, sigHex *string) *string {
	return cryptoEcrecover(hashHex, sigHex)
}

func cryptoEcrecoverCanonical(hashHex *string, sigHex *string) *string {
	return cryptoEcrecover(hashHex, sigHex)
}

func cryptoRlpDecode(hexData *string) *string { return nil }

//go:wasmimport env abort
func abort(msg, file *string, line, column *int32) { return }

//go:wasmimport env revert
func revert(msg, symbol *string) { return }
