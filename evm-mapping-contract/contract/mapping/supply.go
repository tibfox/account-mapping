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

// GetSupply reads the per-asset supply record.
//
// MED-133 (m59 F3): a MISSING key legitimately yields a zero Supply (no
// bridged balance yet). But a key that EXISTS yet decodes to fewer than 4
// fields — or whose fields fail to parse — is CORRUPT (e.g. a layout
// migration that changed the encoding). Pre-fix this silently returned
// Supply{} and the caller wrote those zeros straight back, PERMANENTLY
// destroying the accounting. Distinguish the two: missing => (zero, nil);
// present-but-malformed => error so the caller aborts WITHOUT clobbering the
// stored record (the whole contract call reverts, preserving state for
// diagnosis/migration).
func GetSupply(asset string) (Supply, error) {
	data := sdk.StateGetObject(supplyKey(asset))
	if data == nil {
		return Supply{}, nil
	}
	fields := strings.Split(*data, "|")
	if len(fields) < 4 {
		return Supply{}, errors.New("GetSupply: corrupt supply record (fewer than 4 fields) — refusing to overwrite")
	}
	active, errA := strconv.ParseInt(fields[0], 10, 64)
	user, errU := strconv.ParseInt(fields[1], 10, 64)
	fee, errF := strconv.ParseInt(fields[2], 10, 64)
	baseFee, errB := strconv.ParseUint(fields[3], 10, 64)
	if errA != nil || errU != nil || errF != nil || errB != nil {
		return Supply{}, errors.New("GetSupply: corrupt supply record (unparseable field) — refusing to overwrite")
	}
	return Supply{Active: active, User: user, Fee: fee, BaseFee: baseFee}, nil
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
	s, err := GetSupply(asset)
	if err != nil {
		return err
	}
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
//
// MED-133 (m59 F3): now returns an error so a corrupt supply read aborts the
// withdrawal handler (reverting the already-applied balance debit) instead of
// silently zeroing the supply record.
func TrackWithdrawal(asset string, userAmount, feeOnVault int64) error {
	s, err := GetSupply(asset)
	if err != nil {
		return err
	}
	// R2-2: route the (userAmount + feeOnVault) sum through SafeAdd64 (mirror
	// TrackDeposit). Pre-fix this was an unguarded int64 add: a wrap would make
	// totalActive negative, and `s.Active -= negative` would INFLATE the
	// bridged-supply oracle — and the floor-at-0 below only ever caught the
	// underflow direction, so the inflation slipped through silently. A wrap is
	// a hard reject now, not a silent floor.
	totalActive, err := SafeAdd64(userAmount, feeOnVault)
	if err != nil {
		return errors.New("TrackWithdrawal: userAmount+feeOnVault overflow")
	}
	// R2-2: checked subtraction so an internal wrap is a hard reject. The
	// floor-at-0 is retained ONLY for the legitimate drift case (a debit
	// slightly exceeding the recorded active total) — never to mask a wrap,
	// which SafeSub64 now rejects before the floor can hide it.
	newActive, err := SafeSub64(s.Active, totalActive)
	if err != nil {
		return errors.New("TrackWithdrawal: active accumulator underflow")
	}
	if newActive < 0 {
		newActive = 0
	}
	newUser, err := SafeSub64(s.User, userAmount)
	if err != nil {
		return errors.New("TrackWithdrawal: user accumulator underflow")
	}
	if newUser < 0 {
		newUser = 0
	}
	s.Active = newActive
	s.User = newUser
	SetSupply(asset, s)
	return nil
}
