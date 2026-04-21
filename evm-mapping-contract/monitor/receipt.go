package monitor

import (
	"encoding/hex"
	"evm-mapping-contract/contract/rlp"
	"strings"
)

// RPCReceipt represents a receipt from eth_getTransactionReceipt.
type RPCReceipt struct {
	Status            string   `json:"status"`
	CumulativeGasUsed string   `json:"cumulativeGasUsed"`
	LogsBloom         string   `json:"logsBloom"`
	Logs              []RPCLog `json:"logs"`
	Type              string   `json:"type"`
	TransactionHash   string   `json:"transactionHash"`
	TransactionIndex  string   `json:"transactionIndex"`
}

// RPCLog represents a log entry from a receipt.
type RPCLog struct {
	Address string   `json:"address"`
	Topics  []string `json:"topics"`
	Data    string   `json:"data"`
}

// EncodeReceipt RLP-encodes a receipt in the format Ethereum uses in the receipt trie.
func EncodeReceipt(r *RPCReceipt) []byte {
	status := HexToUint(r.Status)
	cumGas := HexToUint(r.CumulativeGasUsed)
	bloom := HexToBytes(r.LogsBloom)

	logItems := make([][]byte, len(r.Logs))
	for i, log := range r.Logs {
		addr := HexToBytes(log.Address)
		topicItems := make([][]byte, len(log.Topics))
		for j, t := range log.Topics {
			topicItems[j] = rlp.EncodeBytes(HexToBytes(t))
		}
		topicsList := rlp.EncodeList(topicItems...)
		data := HexToBytes(log.Data)
		logItems[i] = rlp.EncodeList(
			rlp.EncodeBytes(addr),
			topicsList,
			rlp.EncodeBytes(data),
		)
	}
	logsList := rlp.EncodeList(logItems...)

	receiptRLP := rlp.EncodeList(
		rlp.EncodeUint64(status),
		rlp.EncodeUint64(cumGas),
		rlp.EncodeBytes(bloom),
		logsList,
	)

	txType := HexToUint(r.Type)
	if txType > 0 {
		return append([]byte{byte(txType)}, receiptRLP...)
	}
	return receiptRLP
}

// BuildReceiptProof builds an MPT proof for a specific receipt index from all block receipts.
func BuildReceiptProof(receipts []*RPCReceipt, targetIndex int) (root []byte, proof [][]byte, encodedReceipt []byte) {
	if targetIndex < 0 || targetIndex >= len(receipts) {
		return nil, nil, nil
	}
	keys := make([][]byte, len(receipts))
	values := make([][]byte, len(receipts))
	for i, r := range receipts {
		keys[i] = rlp.EncodeUint64(uint64(i))
		values[i] = EncodeReceipt(r)
	}

	trie := BuildTrie(keys, values)
	root = TrieRoot(trie)

	targetKey := rlp.EncodeUint64(uint64(targetIndex))
	proof = GenerateProof(trie, targetKey)
	encodedReceipt = values[targetIndex]

	return root, proof, encodedReceipt
}

func HexToBytes(s string) []byte {
	s = strings.TrimPrefix(s, "0x")
	b, _ := hex.DecodeString(s)
	return b
}

func HexToUint(s string) uint64 {
	s = strings.TrimPrefix(s, "0x")
	var v uint64
	for _, c := range s {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= uint64(c - '0')
		case c >= 'a' && c <= 'f':
			v |= uint64(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			v |= uint64(c - 'A' + 10)
		}
	}
	return v
}

// BuildTxProof builds an MPT proof for a transaction at targetIndex from all block transactions.
// Used for native ETH deposits (verified against transactionsRoot, not receiptsRoot).
func BuildTxProof(txs []*RPCTx, targetIndex int) (root []byte, proof [][]byte, encodedTx []byte) {
	if targetIndex < 0 || targetIndex >= len(txs) {
		return nil, nil, nil
	}
	keys := make([][]byte, len(txs))
	values := make([][]byte, len(txs))
	for i, tx := range txs {
		keys[i] = rlp.EncodeUint64(uint64(i))
		values[i] = EncodeTx(tx)
	}

	trie := BuildTrie(keys, values)
	root = TrieRoot(trie)

	targetKey := rlp.EncodeUint64(uint64(targetIndex))
	proof = GenerateProof(trie, targetKey)
	encodedTx = values[targetIndex]

	return root, proof, encodedTx
}
