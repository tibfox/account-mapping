package mapping

import (
	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
	"math"
	"strconv"
	"testing"
)

// TestReview6_M8_AddGasReserveOverflow — review6 M8. Pre-fix, addGasReserve
// performed an unchecked `current + amount` on the gas-reserve accumulator
// and wrote whatever int64 result fell out, so a large positive top-up could
// wrap the stored value to a negative number. The audit fix routes the add
// through SafeAdd64; on overflow the reserve is left untouched and an error
// is surfaced. This test exercises three flows:
//
//   1. Initial reserve = 0, modest amount succeeds and the new reserve is
//      persisted.
//   2. Initial reserve = 0, MaxInt64 amount succeeds (0 + MaxInt64 fits).
//      The interesting overflow case (3) uses a pre-seeded high reserve.
//   3. Pre-seeded reserve = MaxInt64-50, +100 overflows; addGasReserve must
//      error and leave the reserve unchanged.
func TestReview6_M8_AddGasReserveOverflow(t *testing.T) {
	t.Run("zero_plus_modest_succeeds", func(t *testing.T) {
		// Proves the happy path writes the new reserve value to state.
		sdk.ResetStubState()
		if err := addGasReserve(100); err != nil {
			t.Fatalf("addGasReserve(100) = %v, want nil", err)
		}
		if got := getGasReserve(); got != 100 {
			t.Fatalf("reserve=%d, want 100", got)
		}
	})

	t.Run("zero_plus_maxint64_succeeds", func(t *testing.T) {
		// Proves addGasReserve does not falsely reject MaxInt64 when starting
		// from zero — the SafeAdd64 guard fires on (a>0 && b>MaxInt64-a) only.
		sdk.ResetStubState()
		if err := addGasReserve(math.MaxInt64); err != nil {
			t.Fatalf("addGasReserve(MaxInt64) from 0 = %v, want nil", err)
		}
		if got := getGasReserve(); got != math.MaxInt64 {
			t.Fatalf("reserve=%d, want MaxInt64", got)
		}
	})

	t.Run("preseeded_plus_overflow_rejected_state_unchanged", func(t *testing.T) {
		// Core M8 case: with a high pre-existing reserve, a top-up that would
		// wrap to negative must error AND leave the stored reserve untouched.
		sdk.ResetStubState()
		const seed = math.MaxInt64 - 50
		sdk.StateSetObject(constants.GasReserveKey, strconv.FormatInt(seed, 10))

		if err := addGasReserve(100); err == nil {
			t.Fatal("expected overflow error, got nil")
		}
		// Reserve must be unchanged after the rejected add.
		if got := getGasReserve(); got != seed {
			t.Fatalf("reserve=%d after rejected overflow, want %d (unchanged)", got, seed)
		}
	})
}
