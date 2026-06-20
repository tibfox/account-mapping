package mapping

import (
	"errors"
	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
	"math"
	"strconv"
)

// SafeAdd64 returns a+b, returning an error on int64 overflow/underflow.
// Exported per CRIT #3 v17 correction B so callers outside `mapping`
// (e.g. handlers.go, supply.go) route balance arithmetic through one
// audited helper.
func SafeAdd64(a, b int64) (int64, error) {
	if a > 0 && b > math.MaxInt64-a {
		return 0, errors.New("overflow")
	}
	if a < 0 && b < math.MinInt64-a {
		return 0, errors.New("underflow")
	}
	return a + b, nil
}

// SafeSub64 returns a-b, returning an error on int64 overflow/underflow.
// R2-2: TrackWithdrawal's supply debit must reject an internal wrap as a hard
// error rather than silently flooring at 0 (a floor on a wrapped value is
// indistinguishable from — and masks — supply inflation). Same exported-helper
// rationale as SafeAdd64.
func SafeSub64(a, b int64) (int64, error) {
	if b < 0 && a > math.MaxInt64+b {
		return 0, errors.New("overflow")
	}
	if b > 0 && a < math.MinInt64+b {
		return 0, errors.New("underflow")
	}
	return a - b, nil
}

// SafeMul64 returns a*b, returning an error on int64 overflow/underflow.
// review6 L1/X3: gas-fee multiplications (`ETHTransferGas * gasFeeCap`,
// `ERC20TransferGas * gasFeeCap`) bypass the `maxFee` cap when forged
// headers from H2 push BaseFeePerGas → arbitrary values that overflow the
// signed product. Route every fee multiplication through this helper so a
// wrap-to-negative becomes a hard reject before any state mutates.
func SafeMul64(a, b int64) (int64, error) {
	if a == 0 || b == 0 {
		return 0, nil
	}
	// Sign-aware bounds. We test by predicting the bound for b given a's
	// sign; the same condition catches both positive and negative overflow.
	if a > 0 {
		if b > 0 {
			if a > math.MaxInt64/b {
				return 0, errors.New("overflow")
			}
		} else { // b < 0
			if b < math.MinInt64/a {
				return 0, errors.New("underflow")
			}
		}
	} else { // a < 0
		if b > 0 {
			if a < math.MinInt64/b {
				return 0, errors.New("underflow")
			}
		} else { // b < 0
			if a < math.MaxInt64/b {
				return 0, errors.New("overflow")
			}
		}
	}
	return a * b, nil
}

// SafeMulUint64 returns a*b for uint64 operands, returning the int64 result
// and an error if the product overflows int64 (the caller's storage type).
// review6 L1/X3: ETHTransferGas / ERC20TransferGas are typed uint64; the
// existing `int64(uint64 * uint64)` pattern can both wrap inside uint64 and
// re-wrap when cast to int64. Convert through this helper so each step is
// explicit.
func SafeMulUint64(a, b uint64) (int64, error) {
	if a == 0 || b == 0 {
		return 0, nil
	}
	// uint64 overflow check first.
	if a > math.MaxUint64/b {
		return 0, errors.New("overflow uint64")
	}
	prod := a * b
	if prod > math.MaxInt64 {
		return 0, errors.New("overflow int64")
	}
	return int64(prod), nil
}

// computeGasFeeCap computes EIP-1559 maxFeePerGas = baseFeePerGas*2 + tip
// with explicit overflow checking. review6 L1/X3 + composition with H2:
// oracle-trusted addBlocks can stamp arbitrary baseFeePerGas; the prior
// `header.BaseFeePerGas*2 + gasTipCap` would wrap silently past 2^63
// and produce a tiny positive value that bypasses the maxFee cap.
func computeGasFeeCap(baseFeePerGas, tipCap uint64) (uint64, error) {
	if baseFeePerGas > math.MaxUint64/2 {
		return 0, errors.New("baseFeePerGas overflow")
	}
	doubled := baseFeePerGas * 2
	if tipCap > math.MaxUint64-doubled {
		return 0, errors.New("gasFeeCap overflow")
	}
	return doubled + tipCap, nil
}

// computeReplaceGasFeeCap is the 3x-baseFee variant used by
// HandleReplaceWithdrawal for stuck-tx replacement bumps. review6 L1/X3
// adversarial-review follow-up: the audit's "four fee-multiplication
// sites" missed this one; route it through the same overflow-checked
// helper for consistency.
func computeReplaceGasFeeCap(baseFeePerGas, tipCap uint64) (uint64, error) {
	if baseFeePerGas > math.MaxUint64/3 {
		return 0, errors.New("baseFeePerGas overflow (3x)")
	}
	tripled := baseFeePerGas * 3
	if tipCap > math.MaxUint64-tripled {
		return 0, errors.New("gasFeeCap overflow")
	}
	return tripled + tipCap, nil
}

func balanceKey(address, asset string) string {
	return constants.BalancePrefix + address + constants.DirPathDelimiter + asset
}

func allowanceKey(owner, spender, asset string) string {
	return constants.AllowancePrefix + owner + constants.DirPathDelimiter + spender + constants.DirPathDelimiter + asset
}

func GetBalance(address, asset string) int64 {
	data := sdk.StateGetObject(balanceKey(address, asset))
	if data == nil {
		return 0
	}
	v, err := strconv.ParseInt(*data, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func SetBalance(address, asset string, amount int64) {
	sdk.StateSetObject(balanceKey(address, asset), strconv.FormatInt(amount, 10))
}

func IncBalance(address, asset string, amount int64) error {
	bal := GetBalance(address, asset)
	newBal, err := SafeAdd64(bal, amount)
	if err != nil {
		return err
	}
	SetBalance(address, asset, newBal)
	return nil
}

func DecBalance(address, asset string, amount int64) bool {
	// CRIT #3: reject non-positive amount. Without this guard, a negative
	// amount drives `bal - amount` upward and SetBalance writes a credit —
	// free vault drain. Signature is bool (not (bool,error)) to preserve
	// every existing caller. Negative/zero amounts are programmer errors,
	// not user-recoverable conditions.
	if amount <= 0 {
		return false
	}
	bal := GetBalance(address, asset)
	if bal < amount {
		return false
	}
	SetBalance(address, asset, bal-amount)
	return true
}

func GetAllowance(owner, spender, asset string) int64 {
	data := sdk.StateGetObject(allowanceKey(owner, spender, asset))
	if data == nil {
		return 0
	}
	v, err := strconv.ParseInt(*data, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func SetAllowance(owner, spender, asset string, amount int64) {
	sdk.StateSetObject(allowanceKey(owner, spender, asset), strconv.FormatInt(amount, 10))
}
