package mapping

import (
	"encoding/binary"
	"errors"
	"eth-mapping-contract/contract/constants"
	ce "eth-mapping-contract/contract/contracterrors"
	"eth-mapping-contract/sdk"
	"math"
	"math/bits"
	"strconv"
)

// ---------------------------------------------------------------------------
// Account balance helpers (compact big-endian binary, matching BTC contract)
// ---------------------------------------------------------------------------

func getAccBal(vscAcc string) int64 {
	s := sdk.StateGetObject(constants.BalancePrefix + vscAcc)
	if s == nil || *s == "" {
		return 0
	}
	var buf [8]byte
	copy(buf[8-len(*s):], *s)
	return int64(binary.BigEndian.Uint64(buf[:]))
}

func setAccBal(vscAcc string, newBal int64) {
	if newBal == 0 {
		sdk.StateDeleteObject(constants.BalancePrefix + vscAcc)
		return
	}
	v := uint64(newBal)
	n := (bits.Len64(v) + 7) / 8
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	sdk.StateSetObject(constants.BalancePrefix+vscAcc, string(buf[8-n:]))
}

func incAccBalance(vscAcc string, amount int64) error {
	bal := getAccBal(vscAcc)
	newBal, err := safeAdd64(bal, amount)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "error incrementing user balance")
	}
	setAccBal(vscAcc, newBal)
	return nil
}

// ---------------------------------------------------------------------------
// Allowance helpers (compact big-endian binary, matching BTC contract)
// ---------------------------------------------------------------------------

func getAllowance(owner, spender string) int64 {
	s := sdk.StateGetObject(constants.AllowancePrefix + owner + constants.DirPathDelimiter + spender)
	if s == nil || *s == "" {
		return 0
	}
	var buf [8]byte
	copy(buf[8-len(*s):], *s)
	return int64(binary.BigEndian.Uint64(buf[:]))
}

func setAllowance(owner, spender string, amount int64) {
	key := constants.AllowancePrefix + owner + constants.DirPathDelimiter + spender
	if amount == 0 {
		sdk.StateDeleteObject(key)
		return
	}
	v := uint64(amount)
	n := (bits.Len64(v) + 7) / 8
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	sdk.StateSetObject(key, string(buf[8-n:]))
}

// ---------------------------------------------------------------------------
// Balance checking with allowance support
// ---------------------------------------------------------------------------

func checkAndDeductBalance(env sdk.Env, account string, amount int64) error {
	callerAddress := env.Caller.String()
	bal := getAccBal(account)
	if bal < amount {
		return ce.NewContractError(
			ce.ErrBalance,
			"account ["+account+"] balance "+strconv.FormatInt(bal, 10)+
				" insufficient needs "+strconv.FormatInt(amount, 10),
		)
	}
	if account != callerAddress {
		allowance := getAllowance(account, callerAddress)
		if allowance < amount {
			return ce.NewContractError(
				ce.ErrNoPermission,
				"allowance ("+strconv.FormatInt(allowance, 10)+
					") insufficient for spend ("+strconv.FormatInt(amount, 10)+
					") by "+callerAddress,
			)
		}
		setAllowance(account, callerAddress, allowance-amount)
	}
	newBal, err := safeSubtract64(bal, amount)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "error decrementing user balance")
	}
	setAccBal(account, newBal)
	return nil
}

// ---------------------------------------------------------------------------
// Auth check
// ---------------------------------------------------------------------------

func checkAuth(env sdk.Env) error {
	if !slicesContains(env.Sender.RequiredAuths, env.Sender.Address) {
		return ce.NewContractError(ce.ErrNoPermission, "active auth required to send funds")
	}
	return nil
}

// slicesContains checks if a slice contains a value (avoids importing slices package).
func slicesContains(s []sdk.Address, v sdk.Address) bool {
	for _, item := range s {
		if item == v {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Safe arithmetic
// ---------------------------------------------------------------------------

func safeAdd64(a, b int64) (int64, error) {
	if a > 0 && b > math.MaxInt64-a {
		return 0, errors.New("overflow detected")
	}
	if a < 0 && b < math.MinInt64-a {
		return 0, errors.New("underflow detected")
	}
	return a + b, nil
}

func safeSubtract64(a, b int64) (int64, error) {
	if b > 0 && a < math.MinInt64+b {
		return 0, errors.New("underflow detected")
	}
	if b < 0 && a > math.MaxInt64+b {
		return 0, errors.New("overflow detected")
	}
	return a - b, nil
}

func StrPtr(s string) *string {
	return &s
}
