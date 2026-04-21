package mapping

import (
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

func TrackDeposit(asset string, userAmount, feeAmount int64) {
	s := GetSupply(asset)
	s.Active += userAmount + feeAmount
	s.User += userAmount
	s.Fee += feeAmount
	SetSupply(asset, s)
}

func TrackWithdrawal(asset string, amount int64) {
	s := GetSupply(asset)
	s.Active -= amount
	if s.Active < 0 {
		s.Active = 0
	}
	s.User -= amount
	if s.User < 0 {
		s.User = 0
	}
	SetSupply(asset, s)
}
