package mapping

import (
	"encoding/hex"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/rlp"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

func TestBuildETHWithdrawalTx(t *testing.T) {
	to := [20]byte{0xde, 0xad, 0xbe, 0xef}
	amount := new(big.Int)
	amount.SetString("1000000000000000000", 10) // 1 ETH

	unsigned := BuildETHWithdrawalTx(1, 5, 2000000000, 30000000000, to, amount)

	if unsigned[0] != 0x02 {
		t.Fatal("expected EIP-1559 prefix 0x02")
	}

	// Decode and verify fields
	items, err := rlp.DecodeList(unsigned[1:])
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 9 {
		t.Fatalf("expected 9 fields, got %d", len(items))
	}
	if items[0].AsUint64() != 1 {
		t.Fatalf("chainId = %d, want 1", items[0].AsUint64())
	}
	if items[1].AsUint64() != 5 {
		t.Fatalf("nonce = %d, want 5", items[1].AsUint64())
	}
}

func TestBuildERC20WithdrawalTx(t *testing.T) {
	tokenAddr := [20]byte{0xa0, 0xb8, 0x69, 0x91} // USDC prefix
	recipient := [20]byte{0xca, 0xfe}
	amount := big.NewInt(1000000) // 1 USDC

	unsigned := BuildERC20WithdrawalTx(1, 10, 2000000000, 30000000000, tokenAddr, recipient, amount)

	if unsigned[0] != 0x02 {
		t.Fatal("expected EIP-1559 prefix")
	}

	items, err := rlp.DecodeList(unsigned[1:])
	if err != nil {
		t.Fatal(err)
	}

	// Check 'to' is the token contract, not the recipient
	toBytes := items[5].AsBytes()
	if len(toBytes) != 20 || toBytes[0] != 0xa0 {
		t.Fatalf("'to' should be token contract, got %x", toBytes)
	}

	// Check value is 0 (ERC-20 transfer sends no ETH)
	valueBytes := items[6].AsBytes()
	if len(valueBytes) != 0 {
		val := new(big.Int).SetBytes(valueBytes)
		if val.Sign() != 0 {
			t.Fatal("ERC-20 tx value should be 0")
		}
	}

	// Check calldata starts with transfer selector
	calldata := items[7].AsBytes()
	if len(calldata) != 68 {
		t.Fatalf("calldata len = %d, want 68", len(calldata))
	}
	if hex.EncodeToString(calldata[:4]) != "a9059cbb" {
		t.Fatal("wrong function selector")
	}
}

func TestSignAndAttach(t *testing.T) {
	privKeyBytes, _ := hex.DecodeString("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	privKey := secp256k1.PrivKeyFromBytes(privKeyBytes)
	uncompressed := privKey.PubKey().SerializeUncompressed()
	addrHash := crypto.Keccak256(uncompressed[1:])
	var expectedAddr [20]byte
	copy(expectedAddr[:], addrHash[12:])

	to := [20]byte{0xde, 0xad}
	amount := big.NewInt(1000000000000000000)
	unsigned := BuildETHWithdrawalTx(1, 0, 2000000000, 30000000000, to, amount)

	sighash := ComputeSighash(unsigned)
	sig := ecdsa.SignCompact(privKey, sighash, false)

	recoveryFlag := sig[0]
	var ethV byte
	if recoveryFlag >= 31 {
		ethV = recoveryFlag - 31
	} else {
		ethV = recoveryFlag - 27
	}

	signed, err := AttachSignature(unsigned, ethV, sig[1:33], sig[33:65])
	if err != nil {
		t.Fatal(err)
	}

	if signed[0] != 0x02 {
		t.Fatal("signed tx should have 0x02 prefix")
	}

	// Decode signed tx and verify 12 fields
	items, err := rlp.DecodeList(signed[1:])
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 12 {
		t.Fatalf("signed tx should have 12 fields, got %d", len(items))
	}

	// Verify ecrecover on the signed tx
	r := items[10].AsBytes()
	s := items[11].AsBytes()
	v := byte(items[9].AsUint64())

	recovered, err := crypto.Ecrecover(sighash, 27+v, padTo32(r), padTo32(s))
	if err != nil {
		t.Fatal("ecrecover failed:", err)
	}
	if recovered != expectedAddr {
		t.Fatalf("recovered %s, want %s", crypto.AddressToHex(recovered), crypto.AddressToHex(expectedAddr))
	}
	t.Logf("signed tx verified: sender=%s, size=%d bytes", crypto.AddressToHex(recovered), len(signed))
}

func TestSplitPipe(t *testing.T) {
	result := splitPipe("a|b|c|d|e|f")
	if len(result) != 6 {
		t.Fatalf("got %d fields, want 6", len(result))
	}
	if result[0] != "a" || result[5] != "f" {
		t.Fatal("field mismatch")
	}
}
