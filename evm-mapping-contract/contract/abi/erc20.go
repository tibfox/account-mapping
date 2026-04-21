package abi

import (
	"encoding/hex"
	"math/big"
)

// keccak256("transfer(address,uint256)")[:4] = 0xa9059cbb
var transferSelectorHex, _ = hex.DecodeString("a9059cbb")
var TransferSelector = transferSelectorHex

func EncodeTransfer(to [20]byte, amount *big.Int) []byte {
	data := make([]byte, 68) // 4 + 32 + 32
	copy(data[0:4], TransferSelector)
	copy(data[16:36], to[:]) // address left-padded to 32 bytes
	amountBytes := amount.Bytes()
	copy(data[68-len(amountBytes):68], amountBytes) // uint256 left-padded
	return data
}
