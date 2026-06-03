package mapping

import (
	"evm-mapping-contract/sdk"
	"testing"
)

// TestReview6_M11_TrackWithdrawalAccounting — review6 M11. Pre-fix,
// TrackWithdrawal only debited s.Active by `userAmount`, leaving the fee
// component of the original deposit (credited to s.Active as part of
// userAmount+feeAmount in TrackDeposit) stranded on the books forever. Net
// effect: s.Active drifted upward by `feeAmount` per roundtrip — the supply
// oracle overstated bridged balance. This test proves the corrected helper
// debits the full vault-paid amount and clamps underflow at zero.
func TestReview6_M11_TrackWithdrawalAccounting(t *testing.T) {
	t.Run("deposit_then_full_withdrawal_zero_drift", func(t *testing.T) {
		// Proves a deposit/withdrawal roundtrip leaves s.Active=0 and s.User=0
		// when the fee paid by the vault is properly debited.
		sdk.ResetStubState()
		const asset = "eth"

		if err := TrackDeposit(asset, 1000, 10); err != nil {
			t.Fatalf("TrackDeposit: %v", err)
		}
		s := GetSupply(asset)
		if s.Active != 1010 || s.User != 1000 || s.Fee != 10 {
			t.Fatalf("after deposit: Active=%d User=%d Fee=%d, want 1010/1000/10",
				s.Active, s.User, s.Fee)
		}

		TrackWithdrawal(asset, 1000, 10)
		s = GetSupply(asset)
		if s.Active != 0 {
			t.Fatalf("Active=%d after withdrawal, want 0 (no drift)", s.Active)
		}
		if s.User != 0 {
			t.Fatalf("User=%d after withdrawal, want 0", s.User)
		}
		if s.Fee != 10 {
			t.Fatalf("Fee=%d after withdrawal, want 10 (fee accumulator unchanged)", s.Fee)
		}
	})

	t.Run("deduct_fee_path_no_vault_fee", func(t *testing.T) {
		// DeductFee=true case: user absorbs the L1 fee from their own
		// balance, so the vault does not pay anything additional. Passing
		// feeOnVault=0 means s.Active is only debited by `userAmount`, and
		// the leftover fee (10) stays in s.Active — that is the user
		// balance the contract never moved off-chain.
		sdk.ResetStubState()
		const asset = "eth"

		if err := TrackDeposit(asset, 1000, 10); err != nil {
			t.Fatalf("TrackDeposit: %v", err)
		}
		TrackWithdrawal(asset, 1000, 0)
		s := GetSupply(asset)
		if s.Active != 10 {
			t.Fatalf("Active=%d after deduct-fee withdrawal, want 10", s.Active)
		}
		if s.User != 0 {
			t.Fatalf("User=%d after withdrawal, want 0", s.User)
		}
	})

	t.Run("underflow_clamped_to_zero", func(t *testing.T) {
		// Proves the clamp guards against negative s.Active / s.User: even
		// when the requested debit exceeds the recorded supply, the value
		// floors at 0 instead of wrapping to a huge positive int64.
		sdk.ResetStubState()
		const asset = "eth"

		SetSupply(asset, Supply{Active: 30, User: 50, Fee: 0, BaseFee: 0})
		TrackWithdrawal(asset, 100, 0) // user-debit exceeds s.User (50)
		s := GetSupply(asset)
		if s.User != 0 {
			t.Fatalf("User=%d, want 0 (clamped)", s.User)
		}
		if s.Active < 0 {
			t.Fatalf("Active=%d (negative)", s.Active)
		}
	})
}
