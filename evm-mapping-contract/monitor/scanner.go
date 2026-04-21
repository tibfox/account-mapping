package monitor

import (
	"encoding/hex"
	"encoding/json"
	"evm-mapping-contract/contract/crypto"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Deposit represents a detected deposit to the vault.
type Deposit struct {
	BlockHeight    uint64
	TxIndex        int
	LogIndex       int    // -1 for native ETH
	TxHash         string
	From           string // sender ETH address (0x...)
	Amount         string // hex amount
	Asset          string // "eth" or token symbol
	TokenAddress   string // empty for native ETH
	DepositType    string // "eth" or "erc20"
	Proof          [][]byte
	EncodedReceipt []byte
	ReceiptsRoot   []byte
}

// Scanner monitors Ethereum blocks for deposits to the vault address.
type Scanner struct {
	RpcURL           string
	VaultAddress     string // 0x... lowercase
	TokenAddresses   map[string]string // address → symbol
	LastScannedBlock uint64
}

// TransferEventSig is keccak256("Transfer(address,address,uint256)")
var TransferEventSig = hex.EncodeToString(crypto.Keccak256([]byte("Transfer(address,address,uint256)")))

// ScanNewBlocks scans from lastScannedBlock+1 to the latest finalized block.
func (s *Scanner) ScanNewBlocks() ([]Deposit, error) {
	finalized, err := s.getFinalizedBlock()
	if err != nil {
		return nil, fmt.Errorf("get finalized block: %w", err)
	}
	if finalized <= s.LastScannedBlock {
		return nil, nil
	}

	var deposits []Deposit
	for h := s.LastScannedBlock + 1; h <= finalized; h++ {
		blockDeposits, err := s.scanBlock(h)
		if err != nil {
			return deposits, fmt.Errorf("scan block %d: %w", h, err)
		}
		deposits = append(deposits, blockDeposits...)
		s.LastScannedBlock = h
	}
	return deposits, nil
}

func (s *Scanner) scanBlock(height uint64) ([]Deposit, error) {
	blockHex := fmt.Sprintf("0x%x", height)

	// Get block with full transactions
	blockData, err := s.rpcCall("eth_getBlockByNumber", fmt.Sprintf(`"%s", true`, blockHex))
	if err != nil {
		return nil, err
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

	vaultLower := strings.ToLower(s.VaultAddress)

	// Find ETH deposits (direct transfers to vault)
	var ethDepositIndices []int
	for i, tx := range block.Transactions {
		if strings.ToLower(tx.To) == vaultLower {
			val := HexToUint(tx.Value)
			if val > 0 {
				ethDepositIndices = append(ethDepositIndices, i)
			}
		}
	}

	// Find ERC-20 deposits (Transfer events to vault)
	var erc20DepositIndices []struct {
		txIndex  int
		logIndex int
		token    string
		symbol   string
	}
	// Check each registered token
	for tokenAddr, symbol := range s.TokenAddresses {
		logs, err := s.filterLogs(height, height, tokenAddr, vaultLower)
		if err != nil {
			continue
		}
		for _, log := range logs {
			erc20DepositIndices = append(erc20DepositIndices, struct {
				txIndex  int
				logIndex int
				token    string
				symbol   string
			}{log.TxIndex, log.LogIndex, tokenAddr, symbol})
		}
	}

	if len(ethDepositIndices) == 0 && len(erc20DepositIndices) == 0 {
		return nil, nil
	}

	// Fetch ALL receipts and build the trie (needed for proofs)
	receipts, err := s.fetchAllReceipts(block.Transactions)
	if err != nil {
		return nil, fmt.Errorf("fetch receipts: %w", err)
	}

	// Build proofs for ETH deposits — uses receipt proofs (the contract verifies
	// the receipt exists in the block, then the receipt's tx hash is known).
	// NOTE: The contract's VerifyETHDeposit uses transactionsRoot for TX proofs.
	// This requires raw TX bytes which need eth_getRawTransactionByHash.
	// TODO: Fetch raw TXs and build TX proofs instead of receipt proofs for ETH.
	// For now, ETH deposits use receipt proofs which the contract must handle.
	var deposits []Deposit
	for _, txIdx := range ethDepositIndices {
		root, proof, encoded := BuildReceiptProof(receipts, txIdx)
		tx := block.Transactions[txIdx]
		deposits = append(deposits, Deposit{
			BlockHeight:    height,
			TxIndex:        txIdx,
			LogIndex:       -1,
			TxHash:         tx.Hash,
			From:           tx.From,
			Amount:         tx.Value,
			Asset:          "eth",
			DepositType:    "eth",
			Proof:          proof,
			EncodedReceipt: encoded,
			ReceiptsRoot:   root,
		})
	}

	// Build proofs for ERC-20 deposits
	for _, dep := range erc20DepositIndices {
		if dep.txIndex < 0 || dep.txIndex >= len(receipts) {
			continue
		}
		root, proof, encoded := BuildReceiptProof(receipts, dep.txIndex)
		if proof == nil {
			continue
		}
		deposits = append(deposits, Deposit{
			BlockHeight:    height,
			TxIndex:        dep.txIndex,
			LogIndex:       dep.logIndex,
			TxHash:         receipts[dep.txIndex].TransactionHash,
			Asset:          dep.symbol,
			TokenAddress:   dep.token,
			DepositType:    "erc20",
			Proof:          proof,
			EncodedReceipt: encoded,
			ReceiptsRoot:   root,
		})
	}

	return deposits, nil
}

type filteredLog struct {
	TxIndex  int
	LogIndex int
}

func (s *Scanner) filterLogs(fromBlock, toBlock uint64, tokenAddr, vaultAddr string) ([]filteredLog, error) {
	// Pad vault address to 32 bytes for topics filter
	vaultPadded := "0x000000000000000000000000" + strings.TrimPrefix(vaultAddr, "0x")

	params := fmt.Sprintf(`{"fromBlock":"0x%x","toBlock":"0x%x","address":"%s","topics":["0x%s",null,"%s"]}`,
		fromBlock, toBlock, tokenAddr, TransferEventSig, vaultPadded)

	data, err := s.rpcCall("eth_getLogs", params)
	if err != nil {
		return nil, err
	}

	var logs []struct {
		TransactionIndex string `json:"transactionIndex"`
		LogIndex         string `json:"logIndex"`
	}
	json.Unmarshal(data, &logs)

	result := make([]filteredLog, len(logs))
	for i, l := range logs {
		result[i] = filteredLog{
			TxIndex:  int(HexToUint(l.TransactionIndex)),
			LogIndex: int(HexToUint(l.LogIndex)),
		}
	}
	return result, nil
}

func (s *Scanner) fetchAllReceipts(txs []struct {
	Hash  string `json:"hash"`
	From  string `json:"from"`
	To    string `json:"to"`
	Value string `json:"value"`
	Input string `json:"input"`
}) ([]*RPCReceipt, error) {
	receipts := make([]*RPCReceipt, len(txs))
	for i, tx := range txs {
		data, err := s.rpcCall("eth_getTransactionReceipt", fmt.Sprintf(`"%s"`, tx.Hash))
		if err != nil {
			return nil, fmt.Errorf("receipt %d: %w", i, err)
		}
		var r RPCReceipt
		json.Unmarshal(data, &r)
		receipts[i] = &r
	}
	return receipts, nil
}

func (s *Scanner) getFinalizedBlock() (uint64, error) {
	data, err := s.rpcCall("eth_getBlockByNumber", `"finalized", false`)
	if err != nil {
		return 0, err
	}
	var block struct {
		Number string `json:"number"`
	}
	json.Unmarshal(data, &block)
	return HexToUint(block.Number), nil
}

func (s *Scanner) rpcCall(method string, params string) (json.RawMessage, error) {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","method":"%s","params":[%s],"id":1}`, method, params)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(s.RpcURL, "application/json", strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)

	var result struct {
		Result json.RawMessage    `json:"result"`
		Error  *struct{ Message string } `json:"error"`
	}
	json.Unmarshal(data, &result)
	if result.Error != nil {
		return nil, fmt.Errorf("%s", result.Error.Message)
	}
	return result.Result, nil
}

// FormatDepositForContract formats a deposit into the MapParams JSON the contract expects.
func (d *Deposit) FormatDepositForContract() map[string]interface{} {
	proofHex := ""
	for _, node := range d.Proof {
		proofHex += hex.EncodeToString(node)
	}

	txData := map[string]interface{}{
		"block_height":     d.BlockHeight,
		"tx_index":         d.TxIndex,
		"raw_hex":          hex.EncodeToString(d.EncodedReceipt),
		"merkle_proof_hex": proofHex,
		"deposit_type":     d.DepositType,
	}
	if d.DepositType == "erc20" {
		txData["log_index"] = d.LogIndex
		txData["token_address"] = d.TokenAddress
	}

	return map[string]interface{}{
		"tx_data":      txData,
		"instructions": []string{},
	}
}
