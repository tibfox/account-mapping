package mapping

import (
	"math/big"
	"strings"
	"testing"

	"evm-mapping-contract/sdk"
)

// TestReview6_C1_HandleExpireWithdrawal_EmptyProofRejected is the direct
// runtime validation of the audit's C1 finding.
//
// The audit (EVM-FORK-CROSSREF-ALLMETHODS-AUDIT-2026-06-02.md §C1) framed
// the bug as:
//
//	"env.BlockHeight (Hive ≈106M) > ps.BlockHeight+5000 (ETH ≈22M+5000)
//	 so env.BlockHeight < expiryHeight is always FALSE → post-window
//	 branch → proof OPTIONAL; any account calls expireWithdrawal(nonce,
//	 {}) with empty proof."
//
// The review6 fix (F3b) makes the L1-proof-of-drop MANDATORY in ALL
// branches — both pre-window AND post-window. This test sets up a
// PendingSpend, calls HandleExpireWithdrawal with proof.Type="" (the
// empty-proof exploit), and asserts the rejection. Two scenarios:
// pre-window (env.BlockHeight < expiryHeight) and post-window
// (env.BlockHeight >= expiryHeight) both reject identically.
//
// This is the on-host equivalent of the buggy 838f98f tip's behavior —
// the pre-fix code would have accepted the empty proof in the post-window
// branch and refunded the user.
func TestReview6_C1_HandleExpireWithdrawal_EmptyProofRejected(t *testing.T) {
	tests := []struct {
		name          string
		envBlock      uint64 // hive height
		psBlockHeight uint64 // eth height stored on the PendingSpend
		callerIsOwner bool
	}{
		{
			name:          "pre-window: env.BlockHeight < expiryHeight",
			envBlock:      10,   // hive height very low
			psBlockHeight: 100,  // eth height; expiry = 100+5000 = 5100
			callerIsOwner: true, // pre-window requires original withdrawer
		},
		{
			name:          "post-window: env.BlockHeight >= expiryHeight (audit's C1 path)",
			envBlock:      1_000_000_000, // hive height huge — simulates mainnet domain mismatch
			psBlockHeight: 100,           // eth height; expiry = 100+5000 = 5100; 1B > 5100
			callerIsOwner: false,         // post-window: anyone may call
		},
		{
			name:          "post-window: original withdrawer too",
			envBlock:      1_000_000_000,
			psBlockHeight: 100,
			callerIsOwner: true,
		},
	}

	const userDID = "did:pkh:eip155:1:0xAAaaAAAaAaAAaAaAAaaaAAAAAAAaaaAaAaaAaaaa"
	const attackerDID = "did:pkh:eip155:1:0xbBBbbbbBBBBBbBbBBBbbbBbBbBBBbbBbbbbBbBbB"
	const vaultAddr = "0x6026449a55b7eb5c1b1a5e33e02e542bbba719ce"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sdk.ResetStubState()

			caller := attackerDID
			if tt.callerIsOwner {
				caller = userDID
			}
			// Drive sdk.GetEnv() via the stub-injected JSON. Env is consumed
			// by HandleExpireWithdrawal to read caller + block height.
			envJSON := `{
				"contract.id": "vsc1Bdummytest",
				"tx.id": "",
				"tx.index": 0,
				"tx.op_index": 0,
				"block.id": "",
				"block.height": ` + uintStr(tt.envBlock) + `,
				"block.timestamp": "",
				"msg.sender": "` + caller + `",
				"msg.caller": "` + caller + `",
				"msg.payer": "` + caller + `",
				"msg.required_auths": ["` + caller + `"],
				"msg.required_posting_auths": [],
				"sender": {},
				"intents": []
			}`
			sdk.StubSetEnvJSON(envJSON)

			// Seed a PendingSpend at nonce=0 (confirmedNonce head).
			ps := PendingSpend{
				Nonce:        0,
				Amount:       big.NewInt(1_000_000_000), // arbitrary positive amount (wei on this base)
				From:         userDID,                   // user owns the pending spend
				To:           "0xdead000000000000000000000000000000000001",
				Asset:        "eth",
				BlockHeight:  tt.psBlockHeight, // ETH-domain height
				VaultAtQueue: vaultAddr,
			}
			StorePendingSpend(ps)
			// SetPendingNonce(1) (matches the unmapETH side after pushing one
			// withdrawal). GetConfirmedNonce returns 0 by default (no
			// confirmedNonce key in state), so head == 0 == ps.Nonce.

			// The C1 exploit call: empty L1ProofOfDrop.
			emptyProof := L1ProofOfDrop{Type: ""}
			err := HandleExpireWithdrawal(0, emptyProof, 1)

			if err == nil {
				t.Fatalf("C1 FIXED check FAILED: HandleExpireWithdrawal with empty proof returned nil — empty proof was ACCEPTED. This is the audit-reported drain.")
			}
			if !strings.Contains(err.Error(), "L1-proof-of-drop is mandatory") {
				// Other valid rejection reasons (pre-window non-original-withdrawer)
				// are also acceptable as long as the empty proof did NOT cause a
				// silent refund. We accept either:
				//   - "L1-proof-of-drop is mandatory" (the F3b explicit guard)
				//   - "window not elapsed and caller is not original withdrawer"
				if !strings.Contains(err.Error(), "window not elapsed") {
					t.Fatalf("C1 unexpected rejection reason: %v (want 'L1-proof-of-drop is mandatory' or 'window not elapsed')", err)
				}
				t.Logf("rejected via pre-window guard (not proof-mandatory, but still a rejection): %v", err)
			} else {
				t.Logf("rejected as expected with proof-mandatory message: %v", err)
			}

			// Assert state was NOT mutated: pending spend still present.
			stillThere := GetPendingSpend(0)
			if stillThere == nil {
				t.Fatalf("PendingSpend was DELETED despite empty-proof rejection — state mutation invariant broken")
			}
			if stillThere.Amount.Cmp(ps.Amount) != 0 {
				t.Fatalf("PendingSpend was mutated unexpectedly")
			}
		})
	}
}

// uintStr formats a uint64 without importing strconv (simple helper).
func uintStr(n uint64) string {
	if n == 0 {
		return "0"
	}
	var out []byte
	for n > 0 {
		out = append([]byte{byte('0' + n%10)}, out...)
		n /= 10
	}
	return string(out)
}
