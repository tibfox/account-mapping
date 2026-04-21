package rlp

import (
	"bytes"
	"math/big"
	"testing"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"single_byte", []byte{0x42}},
		{"short_string", []byte("dog")},
		{"32_byte_hash", bytes.Repeat([]byte{0xab}, 32)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := EncodeBytes(tt.data)
			decoded, _, err := Decode(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decoded.AsBytes(), tt.data) {
				if tt.data == nil && len(decoded.AsBytes()) == 0 {
					return
				}
				t.Fatalf("round trip failed: got %x, want %x", decoded.AsBytes(), tt.data)
			}
		})
	}
}

func TestEncodeUint64(t *testing.T) {
	tests := []struct {
		val    uint64
		expect []byte
	}{
		{0, []byte{0x80}},
		{1, []byte{0x01}},
		{127, []byte{0x7f}},
		{128, []byte{0x81, 0x80}},
		{1024, []byte{0x82, 0x04, 0x00}},
	}

	for _, tt := range tests {
		encoded := EncodeUint64(tt.val)
		if !bytes.Equal(encoded, tt.expect) {
			t.Fatalf("EncodeUint64(%d) = %x, want %x", tt.val, encoded, tt.expect)
		}
		decoded, _, err := Decode(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.AsUint64() != tt.val {
			t.Fatalf("round trip uint64: got %d, want %d", decoded.AsUint64(), tt.val)
		}
	}
}

func TestEncodeBigInt(t *testing.T) {
	val := new(big.Int)
	val.SetString("1000000000000000000", 10) // 1 ETH in wei

	encoded := EncodeBigInt(val)
	decoded, _, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	result := new(big.Int).SetBytes(decoded.AsBytes())
	if result.Cmp(val) != 0 {
		t.Fatalf("BigInt round trip: got %s, want %s", result, val)
	}
}

func TestEncodeList(t *testing.T) {
	// ["cat", "dog"]
	encoded := EncodeList(EncodeBytes([]byte("cat")), EncodeBytes([]byte("dog")))
	items, err := DecodeList(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("list len=%d, want 2", len(items))
	}
	if string(items[0].Data) != "cat" {
		t.Fatalf("items[0]=%s, want cat", items[0].Data)
	}
	if string(items[1].Data) != "dog" {
		t.Fatalf("items[1]=%s, want dog", items[1].Data)
	}
}

func TestEncodeNestedList(t *testing.T) {
	inner := EncodeList(EncodeUint64(1), EncodeUint64(2))
	outer := EncodeList(inner, EncodeUint64(3))

	items, err := DecodeList(outer)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("outer len=%d, want 2", len(items))
	}
	if !items[0].IsList || len(items[0].Children) != 2 {
		t.Fatal("inner should be list of 2")
	}
	if items[0].Children[0].AsUint64() != 1 {
		t.Fatalf("inner[0]=%d, want 1", items[0].Children[0].AsUint64())
	}
	if items[1].AsUint64() != 3 {
		t.Fatalf("outer[1]=%d, want 3", items[1].AsUint64())
	}
}

func TestEncodeAddress(t *testing.T) {
	var addr [20]byte
	for i := range addr {
		addr[i] = byte(i + 1)
	}
	encoded := EncodeAddress(addr)
	decoded, _, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Data) != 20 {
		t.Fatalf("addr len=%d, want 20", len(decoded.Data))
	}
	if decoded.Data[0] != 1 || decoded.Data[19] != 20 {
		t.Fatalf("addr data mismatch")
	}
}
