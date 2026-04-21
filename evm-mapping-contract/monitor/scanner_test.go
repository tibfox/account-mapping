package monitor

import (
	"bytes"
	"encoding/json"
	"evm-mapping-contract/contract/mpt"
	"evm-mapping-contract/contract/rlp"
	"fmt"
	"testing"
)

func TestScannerProofsAgainstRealMainnet(t *testing.T) {
	s := &Scanner{
		RpcURL:       "https://ethereum-rpc.publicnode.com",
		VaultAddress: "0x7800d68d588d6cb9385f4bb15cd1a375c8b061e6",
		TokenAddresses: map[string]string{
			"0xA0b86991c6218b36c1d19D4a2e9Eb0Ce3606eB48": "usdc",
		},
	}

	finalized, err := s.getFinalizedBlock()
	if err != nil {
		t.Skip("cannot connect:", err)
	}
	// Use a fixed block to avoid race between fetches
	blockHeight := finalized - 5
	blockHex := fmt.Sprintf("0x%x", blockHeight)
	t.Logf("Testing block %d", blockHeight)

	blockData, err := s.rpcCall("eth_getBlockByNumber", fmt.Sprintf(`"%s", true`, blockHex))
	if err != nil {
		t.Fatal(err)
	}

	var block struct {
		Transactions []struct {
			Hash  string `json:"hash"`
			From  string `json:"from"`
			To    string `json:"to"`
			Value string `json:"value"`
			Input string `json:"input"`
		} `json:"transactions"`
		ReceiptsRoot string `json:"receiptsRoot"`
	}
	json.Unmarshal(blockData, &block)
	txCount := len(block.Transactions)
	t.Logf("TXs: %d, receiptsRoot: %s", txCount, block.ReceiptsRoot)

	if txCount == 0 {
		t.Skip("empty block")
	}

	receipts, err := s.fetchAllReceipts(block.Transactions)
	if err != nil {
		t.Fatal(err)
	}

	expectedRoot := HexToBytes(block.ReceiptsRoot)

	// Test first, middle, and last receipt proofs
	indices := []int{0, txCount / 2, txCount - 1}
	for _, idx := range indices {
		root, proof, encoded := BuildReceiptProof(receipts, idx)
		if !bytes.Equal(root, expectedRoot) {
			t.Fatalf("receipt[%d]: root mismatch", idx)
		}

		var rootHash [32]byte
		copy(rootHash[:], root)
		key := rlp.EncodeUint64(uint64(idx))
		value, err := mpt.VerifyProof(rootHash, key, proof)
		if err != nil {
			proofSizes := ""
			for i, n := range proof {
				proofSizes += fmt.Sprintf(" node%d=%dB", i, len(n))
			}
			t.Fatalf("receipt[%d]: verify failed: %v (proof:%s)", idx, err, proofSizes)
		}
		if !bytes.Equal(value, encoded) {
			t.Fatalf("receipt[%d]: value mismatch", idx)
		}
		t.Logf("receipt[%d]: VERIFIED ✓ (proof=%dB receipt=%dB)", idx, totalProofBytes(proof), len(encoded))
	}

	t.Log("")
	t.Log("=== ALL PROOFS VERIFIED AGAINST REAL ETHEREUM MAINNET ===")
}

func totalProofBytes(proof [][]byte) int {
	n := 0
	for _, p := range proof {
		n += len(p)
	}
	return n
}
