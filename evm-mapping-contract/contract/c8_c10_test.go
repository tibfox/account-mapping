package main

import (
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// End-to-end reproduction of pentest finding EVM-C8.
//
// Bug: setVerifierContract accepted an empty contract_id. The
// readState path then sees vcid != "" as false and falls back to
// sdk.StateGetObject — i.e. back to BLS-oracle headers (or the
// empty state). An attacker who got owner access for one moment
// could regress ZK → BLS by passing "".
//
// Fix: reject empty verifier-contract IDs in dispatchAdmin's
// setVerifierContract case. PR #7 routed the setter through the
// propose/execute timelock, so the empty-id guard moved there
// (EVM-C1's immutability was superseded by the timelock).

func TestEVMC8_SetVerifierContractRejectsEmpty(t *testing.T) {
	sdk.ResetTestStateStore()

	// First set goes through — establishes the verifier.
	first := `{"contract_id":"vsc1Verifier"}`
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("first set should not panic: %v", r)
			}
		}()
		dispatchAdmin("setVerifierContract", []byte(first))
	}()

	// Try to set an empty contract_id. The empty-rejection guard fires
	// in dispatchAdmin regardless of prior state, so a fresh deploy can
	// never land an empty verifier id.
	sdk.ResetTestStateStore()
	empty := `{"contract_id":""}`
	var panicValue interface{}
	func() {
		defer func() { panicValue = recover() }()
		dispatchAdmin("setVerifierContract", []byte(empty))
	}()

	if panicValue == nil {
		got := sdk.StateGetObject(constants.VerifierContractIdKey)
		if got != nil && *got == "" {
			t.Fatalf(
				"EVM-C8 leak: setVerifierContract accepted an empty contract_id. " +
					"readState falls back to BLS-oracle state when verifier id is empty.")
		}
	}
	msg, _ := panicValue.(string)
	if !strings.Contains(strings.ToLower(msg), "empty") &&
		!strings.Contains(strings.ToLower(msg), "verifier") {
		t.Errorf("expected empty/verifier-related abort, got: %v", panicValue)
	}
}
