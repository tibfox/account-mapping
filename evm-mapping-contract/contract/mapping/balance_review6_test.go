package mapping

import (
	"evm-mapping-contract/sdk"
	"math"
	"testing"
)

// TestReview6_L1X3_SafeMul64 — review6 L1/X3 makes every signed gas-fee
// multiplication overflow-checked. Pre-fix, `ETHTransferGas * gasFeeCap` and
// `ERC20TransferGas * gasFeeCap` wrapped silently when a forged H2 header
// supplied a huge BaseFeePerGas, bypassing the maxFee cap. SafeMul64 must
// reject every wrap-to-negative case rather than returning a tiny product.
func TestReview6_L1X3_SafeMul64(t *testing.T) {
	t.Run("zero_times_anything", func(t *testing.T) {
		// Proves the zero-fast-path returns (0, nil) — no spurious error.
		got, err := SafeMul64(0, math.MaxInt64)
		if err != nil || got != 0 {
			t.Fatalf("0 * MaxInt64 = (%d, %v), want (0, nil)", got, err)
		}
		got, err = SafeMul64(math.MinInt64, 0)
		if err != nil || got != 0 {
			t.Fatalf("MinInt64 * 0 = (%d, %v), want (0, nil)", got, err)
		}
	})

	t.Run("max_times_one_no_overflow", func(t *testing.T) {
		// Proves we do not falsely reject MaxInt64 * 1.
		got, err := SafeMul64(math.MaxInt64, 1)
		if err != nil || got != math.MaxInt64 {
			t.Fatalf("MaxInt64 * 1 = (%d, %v), want (MaxInt64, nil)", got, err)
		}
	})

	t.Run("positive_overflow_detected", func(t *testing.T) {
		// (MaxInt64/2 + 1) * 2 wraps to a negative value pre-fix; must error.
		_, err := SafeMul64(math.MaxInt64/2+1, 2)
		if err == nil {
			t.Fatal("expected overflow error, got nil")
		}
	})

	t.Run("min_times_negative_one_overflow", func(t *testing.T) {
		// MinInt64 * -1 cannot fit in int64 (= MaxInt64+1) — must error.
		_, err := SafeMul64(math.MinInt64, -1)
		if err == nil {
			t.Fatal("expected overflow error for MinInt64 * -1, got nil")
		}
	})
}

// TestReview6_L1X3_SafeMulUint64 — review6 L1/X3 separately covers the
// uint64-typed gas constants (ETHTransferGas, ERC20TransferGas). The helper
// must catch both the uint64 wrap and the subsequent int64 narrowing.
func TestReview6_L1X3_SafeMulUint64(t *testing.T) {
	t.Run("zero_fast_path", func(t *testing.T) {
		// Proves the zero short-circuit returns (0, nil) for either operand.
		got, err := SafeMulUint64(0, math.MaxUint64)
		if err != nil || got != 0 {
			t.Fatalf("0 * MaxUint64 = (%d, %v), want (0, nil)", got, err)
		}
	})

	t.Run("half_max_uint_times_two_no_overflow", func(t *testing.T) {
		// MaxUint64/2 * 2 fits in uint64 but exceeds MaxInt64; must catch the
		// int64-narrowing step rather than silently wrapping to negative.
		_, err := SafeMulUint64(math.MaxUint64/2, 2)
		if err == nil {
			t.Fatal("expected int64-overflow error for (MaxUint64/2)*2")
		}
	})

	t.Run("over_half_max_uint_overflows_uint64", func(t *testing.T) {
		// (MaxUint64/2 + 1) * 2 wraps inside uint64 itself; helper must
		// reject before any int64 cast.
		_, err := SafeMulUint64(math.MaxUint64/2+1, 2)
		if err == nil {
			t.Fatal("expected uint64-overflow error for (MaxUint64/2+1)*2")
		}
	})

	t.Run("max_uint_times_one_overflows_int64", func(t *testing.T) {
		// MaxUint64 fits uint64 trivially but exceeds MaxInt64; the second
		// check (int64 narrowing) must trip.
		_, err := SafeMulUint64(math.MaxUint64, 1)
		if err == nil {
			t.Fatal("expected int64-overflow error for MaxUint64*1")
		}
	})

	t.Run("modest_product_ok", func(t *testing.T) {
		// Sanity: small product is returned exactly as int64.
		got, err := SafeMulUint64(1_000_000, 2_000_000)
		if err != nil || got != 2_000_000_000_000 {
			t.Fatalf("1e6 * 2e6 = (%d, %v), want (2e12, nil)", got, err)
		}
	})
}

// TestReview6_L1X3_ComputeGasFeeCap — review6 L1/X3 the EIP-1559 maxFeePerGas
// formula `baseFeePerGas*2 + tip` must reject inputs that would wrap. Pre-fix,
// a malicious BaseFeePerGas > MaxUint64/2 wrapped to a tiny value and bypassed
// the configured maxFee cap downstream.
func TestReview6_L1X3_ComputeGasFeeCap(t *testing.T) {
	t.Run("normal_case", func(t *testing.T) {
		// 1 gwei base, 2 gwei tip → 2*1e9 + 2e9 = 4e9.
		got, err := computeGasFeeCap(1_000_000_000, 2_000_000_000)
		if err != nil || got != 4_000_000_000 {
			t.Fatalf("computeGasFeeCap(1e9,2e9) = (%d, %v), want (4e9, nil)", got, err)
		}
	})

	t.Run("base_over_half_max_rejected", func(t *testing.T) {
		// BaseFeePerGas > MaxUint64/2 — doubling wraps. Must reject.
		_, err := computeGasFeeCap(math.MaxUint64/2+1, 0)
		if err == nil {
			t.Fatal("expected baseFeePerGas overflow")
		}
	})

	t.Run("tip_pushes_sum_over_max", func(t *testing.T) {
		// Base just under threshold so doubled fits, but tip pushes the
		// sum past MaxUint64.
		base := uint64(math.MaxUint64 / 2)        // doubled = MaxUint64-1
		tip := uint64(math.MaxUint64) // far larger than MaxUint64-doubled
		_, err := computeGasFeeCap(base, tip)
		if err == nil {
			t.Fatal("expected gasFeeCap overflow when tip pushes past max")
		}
	})
}

// TestReview6_L1X3_ComputeReplaceGasFeeCap — review6 L1/X3 adversarial-review
// follow-up. The 3x-baseFee variant used by HandleReplaceWithdrawal was the
// missing fee-multiplication site; it must reject inputs > MaxUint64/3.
func TestReview6_L1X3_ComputeReplaceGasFeeCap(t *testing.T) {
	t.Run("normal_case", func(t *testing.T) {
		got, err := computeReplaceGasFeeCap(1_000_000_000, 1_000_000_000)
		if err != nil || got != 4_000_000_000 {
			t.Fatalf("computeReplaceGasFeeCap(1e9,1e9) = (%d, %v), want (4e9, nil)", got, err)
		}
	})

	t.Run("base_over_third_max_rejected", func(t *testing.T) {
		_, err := computeReplaceGasFeeCap(math.MaxUint64/3+1, 0)
		if err == nil {
			t.Fatal("expected baseFeePerGas overflow (3x)")
		}
	})
}

// TestReview6_L2X2_IncBalanceOverflowRejected — review6 L2/X2 verifies the
// overflow ERROR PATH in IncBalance is reachable: with the user already at
// MaxInt64-1, a refund of +2 must fail rather than wrapping the stored
// balance to a negative value. This is the same SafeAdd64 path the escape-
// hatch handlers (HandleClearNonce, HandleExpireWithdrawal,
// HandleCancelMyWithdrawal) now hard-fail on instead of silently corrupting.
func TestReview6_L2X2_IncBalanceOverflowRejected(t *testing.T) {
	sdk.ResetStubState()
	const addr = "hive:alice"
	const asset = "eth"

	SetBalance(addr, asset, math.MaxInt64-1)
	if err := IncBalance(addr, asset, 2); err == nil {
		t.Fatal("expected overflow error on IncBalance(MaxInt64-1, +2)")
	}
	// Balance must be unchanged after the rejected increment.
	if got := GetBalance(addr, asset); got != math.MaxInt64-1 {
		t.Fatalf("balance changed after error: got %d, want MaxInt64-1", got)
	}

	// Sanity: small increment still works.
	SetBalance(addr, asset, 100)
	if err := IncBalance(addr, asset, 50); err != nil {
		t.Fatalf("unexpected error on normal IncBalance: %v", err)
	}
	if got := GetBalance(addr, asset); got != 150 {
		t.Fatalf("normal IncBalance = %d, want 150", got)
	}
}

// TestReview6_SafeAdd64 — review6 covers SafeAdd64 directly so the
// overflow/underflow paths used everywhere (IncBalance, addGasReserve,
// TrackDeposit) are validated in isolation.
func TestReview6_SafeAdd64(t *testing.T) {
	t.Run("normal_add", func(t *testing.T) {
		got, err := SafeAdd64(100, 200)
		if err != nil || got != 300 {
			t.Fatalf("100+200 = (%d, %v), want (300, nil)", got, err)
		}
	})

	t.Run("positive_overflow", func(t *testing.T) {
		_, err := SafeAdd64(math.MaxInt64, 1)
		if err == nil {
			t.Fatal("expected overflow on MaxInt64+1")
		}
	})

	t.Run("negative_underflow", func(t *testing.T) {
		_, err := SafeAdd64(math.MinInt64, -1)
		if err == nil {
			t.Fatal("expected underflow on MinInt64-1")
		}
	})

	t.Run("max_plus_zero_ok", func(t *testing.T) {
		got, err := SafeAdd64(math.MaxInt64, 0)
		if err != nil || got != math.MaxInt64 {
			t.Fatalf("MaxInt64+0 = (%d, %v), want (MaxInt64, nil)", got, err)
		}
	})
}
