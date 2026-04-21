package crypto

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

func nativeKeccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}

func nativeEcrecover(hash []byte, v byte, r, s []byte) ([20]byte, error) {
	var addr [20]byte
	sig := make([]byte, 65)
	sig[0] = v
	copy(sig[1:33], r)
	copy(sig[33:65], s)
	pubKey, _, err := ecdsa.RecoverCompact(sig, hash)
	if err != nil {
		return addr, err
	}
	uncompressed := pubKey.SerializeUncompressed()
	addrHash := nativeKeccak256(uncompressed[1:])
	copy(addr[:], addrHash[12:])
	return addr, nil
}

func pubKeyToAddress(pubKey *secp256k1.PublicKey) [20]byte {
	var addr [20]byte
	uncompressed := pubKey.SerializeUncompressed()
	addrHash := nativeKeccak256(uncompressed[1:])
	copy(addr[:], addrHash[12:])
	return addr
}

func TestKeccak256(t *testing.T) {
	got := hex.EncodeToString(nativeKeccak256([]byte("hello")))
	want := "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
	if got != want {
		t.Fatalf("keccak256('hello') = %s, want %s", got, want)
	}
}

func TestKeccak256Empty(t *testing.T) {
	got := hex.EncodeToString(nativeKeccak256([]byte{}))
	want := "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	if got != want {
		t.Fatalf("keccak256('') = %s, want %s", got, want)
	}
}

func TestKeccak256TransferEventSig(t *testing.T) {
	got := hex.EncodeToString(nativeKeccak256([]byte("Transfer(address,address,uint256)")))
	want := "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	if got != want {
		t.Fatalf("Transfer event sig = %s, want %s", got, want)
	}
}

func TestEcrecover(t *testing.T) {
	privKeyBytes, _ := hex.DecodeString("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	privKey := secp256k1.PrivKeyFromBytes(privKeyBytes)

	expectedAddr := pubKeyToAddress(privKey.PubKey())
	knownAddr := "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
	if !strings.EqualFold(AddressToHex(expectedAddr), knownAddr) {
		t.Fatalf("derived %s != known %s", AddressToHex(expectedAddr), knownAddr)
	}

	msgHash := nativeKeccak256([]byte("test message"))
	sig := ecdsa.SignCompact(privKey, msgHash, false)

	recovered, err := nativeEcrecover(msgHash, sig[0], sig[1:33], sig[33:65])
	if err != nil {
		t.Fatal(err)
	}
	if recovered != expectedAddr {
		t.Fatalf("ecrecover: got %s, want %s", AddressToHex(recovered), AddressToHex(expectedAddr))
	}
}

func TestAddressToDID(t *testing.T) {
	addr, _ := HexToAddress("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")
	did := AddressToDID(addr, 1)
	want := "did:pkh:eip155:1:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
	if did != want {
		t.Fatalf("got %s, want %s", did, want)
	}
}

func TestHexToAddress(t *testing.T) {
	addr, err := HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0Ce3606eB48")
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(addr[:]) != "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48" {
		t.Fatalf("address mismatch: %x", addr)
	}
}
