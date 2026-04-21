package rlp

import "math/big"

func EncodeBytes(b []byte) []byte {
	if len(b) == 1 && b[0] <= 0x7f {
		return b
	}
	return append(encodeLength(len(b), 0x80), b...)
}

func EncodeUint64(v uint64) []byte {
	if v == 0 {
		return []byte{0x80}
	}
	b := bigEndianUint64(v)
	return EncodeBytes(b)
}

func EncodeBigInt(v *big.Int) []byte {
	if v == nil || v.Sign() == 0 {
		return []byte{0x80}
	}
	b := v.Bytes()
	return EncodeBytes(b)
}

func EncodeList(items ...[]byte) []byte {
	var payload []byte
	for _, item := range items {
		payload = append(payload, item...)
	}
	return append(encodeLength(len(payload), 0xc0), payload...)
}

func EncodeAddress(addr [20]byte) []byte {
	return EncodeBytes(addr[:])
}

func encodeLength(length int, offset byte) []byte {
	if length <= 55 {
		return []byte{offset + byte(length)}
	}
	lenBytes := bigEndianUint64(uint64(length))
	return append([]byte{offset + 55 + byte(len(lenBytes))}, lenBytes...)
}

func bigEndianUint64(v uint64) []byte {
	if v == 0 {
		return nil
	}
	var buf [8]byte
	n := 0
	for i := 7; i >= 0; i-- {
		buf[i] = byte(v)
		v >>= 8
		if v == 0 {
			n = i
			break
		}
	}
	return buf[n:]
}
