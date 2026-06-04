package mapping

import (
	"math"
	"math/big"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// Pentest finding EVM-C10 (now structural).
//
// Original bug: addGasReserve did `current + amount` on int64 with no
// overflow check, so a reserve near MaxInt64 could wrap negative. The
// original fix clamped to MaxInt64.
//
// big.Int/wei migration: the gas reserve is now a *big.Int (full wei), so
// the int64 overflow that motivated EVM-C10 is structurally impossible —
// addGasReserve never wraps and never needs to clamp. This test pins the
// new invariant: a reserve past the old int64 ceiling accumulates EXACTLY,
// neither wrapping negative (the original bug) nor clamping (the original fix).
func TestEVMC10_AddGasReserveDoesNotOverflow(t *testing.T) {
	sdk.ResetTestStateStore()

	// Seed the reserve just below the old int64 ceiling.
	near := new(big.Int).Sub(big.NewInt(math.MaxInt64), big.NewInt(100)) // MaxInt64 - 100
	sdk.StateSetObject(constants.GasReserveKey, near.String())

	addGasReserve(big.NewInt(1000))

	got := getGasReserve()
	if got.Sign() < 0 {
		t.Fatalf("EVM-C10 leak: gas reserve went negative — big.Int must never wrap. got %s", got)
	}
	want := new(big.Int).Add(near, big.NewInt(1000)) // MaxInt64 + 900 — past the int64 ceiling
	if got.Cmp(want) != 0 {
		t.Fatalf("expected exact accumulation to %s (no wrap, no clamp), got %s", want, got)
	}
}
