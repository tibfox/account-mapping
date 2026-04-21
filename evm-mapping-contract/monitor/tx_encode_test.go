package monitor

import (
	"bytes"
	"encoding/json"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/mpt"
	"evm-mapping-contract/contract/rlp"
	"testing"
)

func TestTxProofAllTypesRealMainnet(t *testing.T) {
	s := &Scanner{RpcURL: "https://ethereum-rpc.publicnode.com"}

	// Block 24910634 has all 4 TX types: 0x0 (30), 0x2 (241), 0x3 (1), 0x4 (2)
	blockData, err := s.rpcCall("eth_getBlockByNumber", `"0x17c1b2a", true`)
	if err != nil {
		t.Skip("no RPC:", err)
	}

	var block struct {
		TransactionsRoot string  `json:"transactionsRoot"`
		Transactions     []RPCTx `json:"transactions"`
	}
	json.Unmarshal(blockData, &block)

	txCount := len(block.Transactions)
	t.Logf("Block 24910634: %d TXs", txCount)

	// Verify every TX hash
	typeCounts := map[string]int{}
	for i, tx := range block.Transactions {
		encoded := EncodeTx(&tx)
		hash := crypto.Keccak256(encoded)
		expected := HexToBytes(tx.Hash)
		if !bytes.Equal(hash, expected) {
			t.Fatalf("TX %d (type %s): hash mismatch", i, tx.Type)
		}
		typeCounts[tx.Type]++
	}
	t.Logf("All %d TX hashes match ✓", txCount)
	for tp, count := range typeCounts {
		t.Logf("  Type %s: %d TXs", tp, count)
	}

	// Build TX trie via BuildTxProof
	txPtrs := make([]*RPCTx, txCount)
	for i := range block.Transactions {
		txPtrs[i] = &block.Transactions[i]
	}

	root, proof0, encoded0 := BuildTxProof(txPtrs, 0)
	expectedRoot := HexToBytes(block.TransactionsRoot)

	if !bytes.Equal(root, expectedRoot) {
		t.Fatal("TRANSACTIONS ROOT MISMATCH")
	}
	t.Log("Transactions root matches ✓")

	// Verify proof for TX[0]
	var rootHash [32]byte
	copy(rootHash[:], root)
	key0 := rlp.EncodeUint64(0)
	value0, err := mpt.VerifyProof(rootHash, key0, proof0)
	if err != nil {
		t.Fatal("MPT verify TX[0]:", err)
	}
	if !bytes.Equal(value0, encoded0) {
		t.Fatal("TX[0] value mismatch")
	}
	t.Logf("TX[0] (type %s) proof verified ✓", block.Transactions[0].Type)

	// Verify proof for one TX of each type
	typeVerified := map[string]bool{}
	for i, tx := range block.Transactions {
		if typeVerified[tx.Type] {
			continue
		}
		_, proof, encoded := BuildTxProof(txPtrs, i)
		key := rlp.EncodeUint64(uint64(i))
		val, err := mpt.VerifyProof(rootHash, key, proof)
		if err != nil {
			t.Fatalf("TX[%d] type %s: MPT verify failed: %v", i, tx.Type, err)
		}
		if !bytes.Equal(val, encoded) {
			t.Fatalf("TX[%d] type %s: value mismatch", i, tx.Type)
		}
		t.Logf("TX[%d] (type %s) proof verified ✓", i, tx.Type)
		typeVerified[tx.Type] = true
	}

	t.Logf("\n=== Go monitor TX proof: %d TXs, %d types, all verified ===", txCount, len(typeCounts))
}
