package crypto

import (
	"encoding/hex"
	"evm-mapping-contract/contract/rlp"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

func TestRealWorldEIP1559TxRoundTrip(t *testing.T) {
	privKeyBytes, _ := hex.DecodeString("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	privKey := secp256k1.PrivKeyFromBytes(privKeyBytes)
	expectedAddr := pubKeyToAddress(privKey.PubKey())

	unsignedRLP := rlp.EncodeList(
		rlp.EncodeUint64(1),
		rlp.EncodeUint64(161138),
		rlp.EncodeUint64(2000000000),
		rlp.EncodeUint64(30000000000),
		rlp.EncodeUint64(21000),
		rlp.EncodeBytes(expectedAddr[:]),
		rlp.EncodeUint64(7),
		rlp.EncodeBytes(nil),
		rlp.EncodeList(),
	)
	unsignedTx := append([]byte{0x02}, unsignedRLP...)
	sighash := nativeKeccak256(unsignedTx)

	sig := ecdsa.SignCompact(privKey, sighash, false)
	var ethV byte
	if sig[0] >= 31 { ethV = sig[0] - 31 } else { ethV = sig[0] - 27 }

	items, _ := rlp.DecodeList(unsignedRLP)
	enc := make([][]byte, 12)
	for i := 0; i < 9; i++ {
		if items[i].IsList { enc[i] = rlp.EncodeList() } else { enc[i] = rlp.EncodeBytes(items[i].AsBytes()) }
	}
	enc[9] = rlp.EncodeUint64(uint64(ethV))
	enc[10] = rlp.EncodeBytes(sig[1:33])
	enc[11] = rlp.EncodeBytes(sig[33:65])
	signedTx := append([]byte{0x02}, rlp.EncodeList(enc...)...)

	parsed, _ := rlp.DecodeList(signedTx[1:])
	if len(parsed) != 12 { t.Fatalf("got %d fields", len(parsed)) }

	unsFields := make([][]byte, 9)
	for i := 0; i < 9; i++ {
		if parsed[i].IsList { unsFields[i] = rlp.EncodeList() } else { unsFields[i] = rlp.EncodeBytes(parsed[i].AsBytes()) }
	}
	recHash := nativeKeccak256(append([]byte{0x02}, rlp.EncodeList(unsFields...)...))

	pR := parsed[10].AsBytes(); pS := parsed[11].AsBytes(); pV := byte(parsed[9].AsUint64())
	rPad := make([]byte, 32); sPad := make([]byte, 32)
	copy(rPad[32-len(pR):], pR); copy(sPad[32-len(pS):], pS)

	recovered, err := nativeEcrecover(recHash, 27+pV, rPad, sPad)
	if err != nil { t.Fatal(err) }
	if recovered != expectedAddr {
		t.Fatalf("recovered %s, want %s", AddressToHex(recovered), AddressToHex(expectedAddr))
	}
	t.Logf("FULL EIP-1559 ROUND-TRIP: chainId=1 nonce=161138 value=7wei sender=%s ✓", AddressToHex(recovered))
}

func TestKeccak256EthereumVectors(t *testing.T) {
	tests := []struct{ input, want string }{
		{"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},
		{"Transfer(address,address,uint256)", "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"},
		{"Approval(address,address,uint256)", "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"},
	}
	for _, tt := range tests {
		if got := hex.EncodeToString(nativeKeccak256([]byte(tt.input))); got != tt.want {
			t.Errorf("keccak256(%q) = %s, want %s", tt.input, got, tt.want)
		}
	}
}

func TestEIP1559SighashFormat(t *testing.T) {
	fields := rlp.EncodeList(
		rlp.EncodeUint64(1), rlp.EncodeUint64(0), rlp.EncodeUint64(2000000000),
		rlp.EncodeUint64(30000000000), rlp.EncodeUint64(21000),
		rlp.EncodeBytes(make([]byte, 20)),
		rlp.EncodeBigInt(big.NewInt(1000000000000000000)),
		rlp.EncodeBytes(nil), rlp.EncodeList(),
	)
	hash := nativeKeccak256(append([]byte{0x02}, fields...))
	if len(hash) != 32 { t.Fatal("wrong hash length") }
	t.Logf("1 ETH transfer sighash: %s", hex.EncodeToString(hash))
}
