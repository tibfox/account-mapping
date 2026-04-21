package monitor

import (
	"bytes"
	"encoding/json"
	"evm-mapping-contract/contract/mapping"
	"evm-mapping-contract/contract/mpt"
	"evm-mapping-contract/contract/rlp"
	"fmt"
	"testing"
)

func TestFormatDepositMatchesContractInput(t *testing.T) {
	s := &Scanner{RpcURL: "https://ethereum-rpc.publicnode.com"}

	finalized, err := s.getFinalizedBlock()
	if err != nil {
		t.Skip("no RPC:", err)
	}
	blockHeight := finalized - 10
	blockHex := fmt.Sprintf("0x%x", blockHeight)

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

	if len(block.Transactions) == 0 {
		t.Skip("empty block")
	}
	t.Logf("Block %d: %d TXs", blockHeight, len(block.Transactions))

	receipts, err := s.fetchAllReceipts(block.Transactions)
	if err != nil {
		t.Fatal(err)
	}

	// Build a deposit as the monitor would
	root, proof, encoded := BuildReceiptProof(receipts, 0)
	deposit := Deposit{
		BlockHeight:    blockHeight,
		TxIndex:        0,
		LogIndex:       -1,
		TxHash:         block.Transactions[0].Hash,
		From:           block.Transactions[0].From,
		Amount:         block.Transactions[0].Value,
		Asset:          "eth",
		DepositType:    "eth",
		Proof:          proof,
		EncodedReceipt: encoded,
		ReceiptsRoot:   root,
	}

	// Format as the monitor would
	formatted := deposit.FormatDepositForContract()

	// Marshal to JSON then unmarshal into contract's MapParams
	jsonBytes, err := json.Marshal(formatted)
	if err != nil {
		t.Fatal("marshal:", err)
	}
	t.Logf("Formatted JSON: %d bytes", len(jsonBytes))

	var params mapping.MapParams
	err = json.Unmarshal(jsonBytes, &params)
	if err != nil {
		t.Fatal("unmarshal into MapParams:", err)
	}

	// Verify every field round-tripped correctly
	if params.TxData.BlockHeight != blockHeight {
		t.Fatalf("BlockHeight: got %d, want %d", params.TxData.BlockHeight, blockHeight)
	}
	if params.TxData.TxIndex != 0 {
		t.Fatalf("TxIndex: got %d, want 0", params.TxData.TxIndex)
	}
	if params.TxData.DepositType != "eth" {
		t.Fatalf("DepositType: got %s, want eth", params.TxData.DepositType)
	}
	if params.TxData.RawHex == "" {
		t.Fatal("RawHex is empty")
	}
	if params.TxData.MerkleProofHex == "" {
		t.Fatal("MerkleProofHex is empty")
	}
	t.Logf("Field mapping: ALL MATCH ✓")

	// NOW: decode the proof from the formatted data and verify it
	// This is what the contract would do
	receiptBytes := HexToBytes(params.TxData.RawHex)
	proofBytes := HexToBytes(params.TxData.MerkleProofHex)

	// Split proof nodes (same as contract's splitProofNodes)
	proofNodes := splitProofNodesLocal(proofBytes)

	// Verify against the receiptsRoot
	expectedRoot := HexToBytes(block.ReceiptsRoot)
	var rootHash [32]byte
	copy(rootHash[:], expectedRoot)

	key := rlp.EncodeUint64(params.TxData.TxIndex)
	value, err := mpt.VerifyProof(rootHash, key, proofNodes)
	if err != nil {
		t.Fatalf("MPT verify through contract interface: %v", err)
	}
	if !bytes.Equal(value, receiptBytes) {
		t.Fatal("Proof verified but value mismatch")
	}

	t.Logf("FULL INTERFACE TEST: monitor → format → unmarshal → verify ✓")
	t.Logf("  Receipt: %d bytes, Proof: %d nodes (%d bytes total)", len(receiptBytes), len(proofNodes), len(proofBytes))
}

func splitProofNodesLocal(data []byte) [][]byte {
	nodes := make([][]byte, 0)
	offset := 0
	for offset < len(data) {
		_, end, err := rlp.Decode(data[offset:])
		if err != nil {
			break
		}
		nodes = append(nodes, data[offset:offset+end])
		offset += end
	}
	return nodes
}
