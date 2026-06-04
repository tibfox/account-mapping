package mapping

import (
	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
	"math/big"
	"strconv"
	"strings"
)

// Supply tracks per-asset solvency totals. The three monetary accumulators
// are *big.Int (full wei / token-native precision, no overflow). BaseFee is
// a per-gas price observation (wei/gas) and stays a uint64 scalar.
type Supply struct {
	Active  *big.Int // total bridged
	User    *big.Int // credited to users
	Fee     *big.Int // protocol fees
	BaseFee uint64   // latest base fee
}

// newSupply returns a zero Supply with non-nil accumulators so callers can
// always do s.Active.Add(...) without a nil check.
func newSupply() Supply {
	return Supply{Active: new(big.Int), User: new(big.Int), Fee: new(big.Int)}
}

func supplyKey(asset string) string {
	return constants.SupplyKey + constants.DirPathDelimiter + asset
}

func GetSupply(asset string) Supply {
	s := newSupply()
	data := sdk.StateGetObject(supplyKey(asset))
	if data == nil {
		return s
	}
	fields := strings.Split(*data, "|")
	if len(fields) < 4 {
		return s
	}
	s.Active = parseAmount(fields[0])
	s.User = parseAmount(fields[1])
	s.Fee = parseAmount(fields[2])
	s.BaseFee, _ = strconv.ParseUint(fields[3], 10, 64)
	return s
}

func SetSupply(asset string, s Supply) {
	data := s.Active.String() + "|" +
		s.User.String() + "|" +
		s.Fee.String() + "|" +
		strconv.FormatUint(s.BaseFee, 10)
	sdk.StateSetObject(supplyKey(asset), data)
}

// TrackDeposit accumulates per-asset supply totals. big.Int accumulators
// cannot overflow, so there is no failure mode and nothing to return.
func TrackDeposit(asset string, userAmount, feeAmount *big.Int) {
	s := GetSupply(asset)
	delta := new(big.Int).Add(userAmount, feeAmount)
	s.Active.Add(s.Active, delta)
	s.User.Add(s.User, userAmount)
	s.Fee.Add(s.Fee, feeAmount)
	SetSupply(asset, s)
}

// TrackWithdrawal subtracts amount from the tracked Active and
// User supply for an asset.
//
// Pentest finding F17: previously this function silently clamped
// negative results to 0. Every public withdrawal path validates the
// user's balance before reaching here, so a negative result can only
// mean some other code path violated that invariant. Abort loudly
// instead so a programming error in a caller is caught immediately
// rather than papered over by silently corrupting the supply counters.
// big.Int/wei: the comparison and subtraction are full-precision.
func TrackWithdrawal(asset string, amount *big.Int) {
	s := GetSupply(asset)
	if amount.Cmp(s.Active) > 0 || amount.Cmp(s.User) > 0 {
		sdk.Abort("supply underflow on TrackWithdrawal: amount " +
			amount.String() + " exceeds tracked supply for asset " + asset)
	}
	s.Active.Sub(s.Active, amount)
	s.User.Sub(s.User, amount)
	SetSupply(asset, s)
}
