package mapping

import (
	"math"
	"testing"
)

// review2 HIGH #16 — the withdrawal/gas-reserve fee was computed as
// int64(gasUnits * (baseFeePerGas*2 + gasTipCap)) with no overflow check.
// A high baseFeePerGas (>= ~219,604 gwei for the 21000-gas path) makes the
// uint64 product exceed MaxInt64; the int64 cast then wraps NEGATIVE, the
// fee/totalDeduct goes negative and the user's balance is inflated instead
// of debited. safeGasFee must reject every overflow rather than wrap.

const gwei = uint64(1_000_000_000)

func TestSafeGasFee_NormalValues(t *testing.T) {
	// 20 gwei base, 2 gwei tip, 21000 gas.
	cap_, fee, err := safeGasFee(21_000, 20*gwei, 2, 2*gwei)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantCap := 20*gwei*2 + 2*gwei // 42 gwei
	if cap_ != wantCap {
		t.Fatalf("gasFeeCap = %d, want %d", cap_, wantCap)
	}
	wantFee := int64(21_000 * wantCap)
	if fee != wantFee {
		t.Fatalf("fee = %d, want %d", fee, wantFee)
	}
	if fee <= 0 {
		t.Fatalf("fee must be positive, got %d", fee)
	}
}

func TestSafeGasFee_RejectsInt64WrapFromHighBaseFee(t *testing.T) {
	// The reported threshold: baseFee >= ~219,604 gwei on the 21000-gas
	// path makes 21000*(2*base+tip) exceed MaxInt64.
	_, fee, err := safeGasFee(21_000, 219_604*gwei, 2, 2*gwei)
	if err == nil {
		t.Fatalf("expected overflow error; got fee=%d (would wrap negative pre-fix)", fee)
	}
}

func TestSafeGasFee_RejectsGasFeeCapAddOverflow(t *testing.T) {
	if _, _, err := safeGasFee(21_000, math.MaxUint64-1, 2, 1_000); err == nil {
		t.Fatalf("expected gas fee cap overflow error")
	}
}

func TestSafeGasFee_RejectsDoublingOverflow(t *testing.T) {
	// baseFeePerGas*2 alone overflows uint64.
	if _, _, err := safeGasFee(21_000, math.MaxUint64/2+1, 2, 0); err == nil {
		t.Fatalf("expected doubling overflow error")
	}
}

// review2 HIGH #16 (4th path) — replaceWithdrawal re-prices at multiplier=3
// and charges no fee, so it calls safeGasFee with gasUnits=0 and only uses
// the gasFeeCap. Pin both the 3x cap math and the gasUnits=0 cap-only path.
func TestSafeGasFee_Multiplier3CapOnly(t *testing.T) {
	cap_, fee, err := safeGasFee(0, 20*gwei, 3, 4*gwei)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantCap := 20*gwei*3 + 4*gwei // 64 gwei
	if cap_ != wantCap {
		t.Fatalf("gasFeeCap = %d, want %d", cap_, wantCap)
	}
	if fee != 0 {
		t.Fatalf("gasUnits=0 must yield fee=0, got %d", fee)
	}
}

// The 3x multiplication must overflow-check just like 2x: a base fee past
// MaxUint64/3 wraps the cap and must be rejected, not signed under-priced.
func TestSafeGasFee_RejectsMultiplier3CapOverflow(t *testing.T) {
	if _, _, err := safeGasFee(0, math.MaxUint64/3+1, 3, 0); err == nil {
		t.Fatalf("expected 3x cap overflow error")
	}
}
