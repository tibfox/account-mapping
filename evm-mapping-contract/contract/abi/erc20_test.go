package abi

import (
	"encoding/hex"
	"math/big"
	"testing"
)

func TestTransferSelector(t *testing.T) {
	got := hex.EncodeToString(TransferSelector)
	want := "a9059cbb"
	if got != want {
		t.Fatalf("transfer selector = %s, want %s", got, want)
	}
}

func TestEncodeTransfer(t *testing.T) {
	to := [20]byte{0xde, 0xad, 0xbe, 0xef}
	amount := big.NewInt(1000000) // 1 USDC

	data := EncodeTransfer(to, amount)

	if len(data) != 68 {
		t.Fatalf("encoded length = %d, want 68", len(data))
	}

	// Check selector
	if hex.EncodeToString(data[:4]) != "a9059cbb" {
		t.Fatal("wrong selector")
	}

	// Check address is at bytes 16-36 (left-padded in 32-byte slot)
	for i := 4; i < 16; i++ {
		if data[i] != 0 {
			t.Fatalf("address padding byte %d = %x, want 0", i, data[i])
		}
	}
	if data[16] != 0xde || data[17] != 0xad {
		t.Fatal("address mismatch")
	}

	// Check amount
	decodedAmount := new(big.Int).SetBytes(data[36:68])
	if decodedAmount.Cmp(amount) != 0 {
		t.Fatalf("amount = %s, want %s", decodedAmount, amount)
	}
}
