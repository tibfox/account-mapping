package mapping

import (
	"encoding/hex"
	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
	"strconv"
)

// Each observed entry: 32-byte txHash + 2-byte index (txIndex or logIndex)
const observedEntrySize = 34

func observedKey(blockHeight uint64) string {
	return constants.ObservedBlockPrefix + strconv.FormatUint(blockHeight, 10)
}

func IsObserved(blockHeight uint64, txHash [32]byte, index uint16) bool {
	data := sdk.StateGetObject(observedKey(blockHeight))
	if data == nil {
		return false
	}
	entries := []byte(*data)
	entry := makeEntry(txHash, index)
	for i := 0; i+observedEntrySize <= len(entries); i += observedEntrySize {
		match := true
		for j := 0; j < observedEntrySize; j++ {
			if entries[i+j] != entry[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func MarkObserved(blockHeight uint64, txHash [32]byte, index uint16) {
	entry := makeEntry(txHash, index)
	existing := sdk.StateGetObject(observedKey(blockHeight))
	var data []byte
	if existing != nil {
		data = append([]byte(*existing), entry...)
	} else {
		data = entry
	}
	sdk.StateSetObject(observedKey(blockHeight), string(data))
}

func makeEntry(txHash [32]byte, index uint16) []byte {
	entry := make([]byte, observedEntrySize)
	copy(entry[:32], txHash[:])
	entry[32] = byte(index >> 8)
	entry[33] = byte(index)
	return entry
}

func TxHashFromHex(s string) ([32]byte, error) {
	var h [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return h, err
	}
	copy(h[:], b)
	return h, nil
}
