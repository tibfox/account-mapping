package mapping

import (
	"errors"
	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
	"strconv"
	"strings"
)

type Supply struct {
	Active   int64 // total bridged
	User     int64 // credited to users
	Fee      int64 // protocol fees
	BaseFee  uint64 // latest base fee
}

func supplyKey(asset string) string {
	return constants.SupplyKey + constants.DirPathDelimiter + asset
}

func GetSupply(asset string) Supply {
	data := sdk.StateGetObject(supplyKey(asset))
	if data == nil {
		return Supply{}
	}
	fields := strings.Split(*data, "|")
	if len(fields) < 4 {
		return Supply{}
	}
	s := Supply{}
	s.Active, _ = strconv.ParseInt(fields[0], 10, 64)
	s.User, _ = strconv.ParseInt(fields[1], 10, 64)
	s.Fee, _ = strconv.ParseInt(fields[2], 10, 64)
	s.BaseFee, _ = strconv.ParseUint(fields[3], 10, 64)
	return s
}

func SetSupply(asset string, s Supply) {
	data := strconv.FormatInt(s.Active, 10) + "|" +
		strconv.FormatInt(s.User, 10) + "|" +
		strconv.FormatInt(s.Fee, 10) + "|" +
		strconv.FormatUint(s.BaseFee, 10)
	sdk.StateSetObject(supplyKey(asset), data)
}

// TrackDeposit accumulates per-asset supply totals. Two unguarded int64
// additions live here per CRIT #3: the inner (userAmount + feeAmount) sum
// and the (s.Active += ...) accumulator. Both must safe-add — wrapping the
// accumulator silently corrupts supply forever.
func TrackDeposit(asset string, userAmount, feeAmount int64) error {
	s := GetSupply(asset)
	delta, err := SafeAdd64(userAmount, feeAmount)
	if err != nil {
		return errors.New("TrackDeposit: userAmount+feeAmount overflow")
	}
	newActive, err := SafeAdd64(s.Active, delta)
	if err != nil {
		return errors.New("TrackDeposit: active accumulator overflow")
	}
	newUser, err := SafeAdd64(s.User, userAmount)
	if err != nil {
		return errors.New("TrackDeposit: user accumulator overflow")
	}
	newFee, err := SafeAdd64(s.Fee, feeAmount)
	if err != nil {
		return errors.New("TrackDeposit: fee accumulator overflow")
	}
	s.Active = newActive
	s.User = newUser
	s.Fee = newFee
	SetSupply(asset, s)
	return nil
}

// TrackWithdrawal accumulates per-asset supply totals on the unmap side.
//
// review6 M11: pre-fix this only deducted `userAmount` from s.Active, so the
// fee portion of the original deposit (credited to s.Active in TrackDeposit
// as part of the userAmount+feeAmount sum) was never debited on the
// withdrawal that ultimately spent it. Net effect: s.Active drifted upward
// by feeAmount on every roundtrip — the supply oracle overstated bridged
// balance, an accounting/insolvency-tracking bug. Track the full debit
// (user value + L1 fee paid by the contract) so s.Active mirrors the real
// vault balance.
//
// userAmount  — gwei units actually unmapped (will appear on L1).
// feeOnVault  — gwei units the contract pays the L1 miner ON BEHALF OF the
//               user. Pass 0 for ERC-20 (gas reserve covers fee separately)
//               or DeductFee=true ETH (fee is netted from amount upstream).
func TrackWithdrawal(asset string, userAmount, feeOnVault int64) {
	s := GetSupply(asset)
	// s.Active reflects total bridged (user + fee component). Deduct both.
	totalActive := userAmount + feeOnVault
	s.Active -= totalActive
	if s.Active < 0 {
		s.Active = 0
	}
	s.User -= userAmount
	if s.User < 0 {
		s.User = 0
	}
	SetSupply(asset, s)
}
