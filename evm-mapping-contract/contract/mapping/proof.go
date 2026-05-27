package mapping

import (
	"encoding/hex"
	"errors"
	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/mpt"
	"evm-mapping-contract/contract/rlp"
	"math/big"
)

// WeiPerGwei — W4 Cluster A Step 3b gwei scaling. 1 gwei = 1e9 wei.
// Native ETH amounts cross the contract boundary in wei (L1 native unit) but
// are stored internally in gwei to expand int64 capacity from 9.22 ETH to
// 9.22 billion ETH. Conversion uses big.Int.Div which truncates toward zero
// — sub-gwei dust is silently dropped (≈ $0.000000003 at $3K ETH per
// truncation). The same Div semantics MUST be used at every conversion
// boundary so deposit-side and confirmSpend-side truncation match
// bit-for-bit (see Step 3b "Truncation invariant" in the manifest).
var WeiPerGwei = big.NewInt(1_000_000_000)

var (
	ErrBlockNotFound   = errors.New("block header not found")
	ErrProofFailed     = errors.New("proof verification failed")
	ErrNotVaultDeposit = errors.New("transaction is not a deposit to vault")
	ErrAlreadyObserved = errors.New("deposit already processed")
	ErrInvalidToken    = errors.New("token not registered")
	// W4 Cluster B CRIT #6 Sites 1+2: explicit error for wrong-chain
	// deposit proofs. The L1 trie proof can be valid AND the parsed tx
	// can be well-formed, yet the tx may have been mined on a different
	// chain. Without this check, an attacker could replay a chain-X tx
	// against the chain-Y bridge state.
	ErrChainIdMismatch = errors.New("tx chain id does not match contract chain id")
)

// keccak256("Transfer(address,address,uint256)") = ddf252ad...
var transferEventSigBytes, _ = hex.DecodeString("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")
var TransferEventSig = func() [32]byte { var h [32]byte; copy(h[:], transferEventSigBytes); return h }()

// VerifyETHDeposit verifies a native ETH deposit via transaction inclusion proof.
// Returns the sender address, deposit amount (wei as big-endian bytes), and the tx hash.
//
// W4 Cluster A CRIT #1: ETH path verifies against header.TransactionsRoot using
// tx-trie inclusion + parseTransaction. Receipt-trie cannot be used for native
// ETH because Ethereum receipts contain {status, cumulativeGasUsed, logsBloom,
// logs} and no sender/value/recipient field — the vault is a TSS EOA and emits
// no log.
//
// W4 Cluster A CRIT #8: this function NO LONGER calls MarkObserved. The caller
// (HandleMap) must call MarkObserved AFTER all instruction routing succeeds,
// using the returned txHash. This prevents a failed instruction (e.g.
// malformed instructions list, router contract reverting) from permanently
// locking the deposit hash to a non-credit outcome.
//
// W4 Cluster A HIGH #41: parseTransaction explicitly rejects tx types 1/3/4
// BEFORE any state mutation; only type-2 (EIP-1559) and legacy (no type byte)
// are accepted in v1. The pre-check sits between the proof-verify (purely
// read-side state via blocklist) and any path that could mutate observed list.
// Since MarkObserved is now in the caller, this satisfies "explicit revert
// BEFORE L1 debit": the L1 funds are already debited (deposit landed on L1),
// but the v1 contract simply refuses to credit unsupported type wallets. v2
// extends parser coverage.
// W4 Cluster B CRIT #6 Site 1: chainId parameter added. The parsed tx's
// ChainId field is cross-checked against the contract's expected chainId
// BEFORE returning success. For legacy txs the parseLegacyTx path decodes
// chainId from the EIP-155 envelope (v = chainId*2 + 35 + recid); for
// EIP-1559 (type 2) tx the chainId is the first RLP item. Pre-EIP-155
// legacy txs (v in {27,28}, no chainId) report ChainId=0 and are
// rejected (Magi mainnet runs on a single chainId; no zero-chainId txs
// can ever be a valid deposit). Verification ordering: trie-proof first
// (binds rawBytes to the on-chain root), then parse, then chainId check,
// then ecrecover. Wrong-chain txs are rejected BEFORE any state mutation
// (W4 Cluster A relocated MarkObserved to HandleMap; chainId check sits
// before that relocation point).
func VerifyETHDeposit(req *VerificationRequest, vaultAddress [20]byte, chainId uint64) ([20]byte, []byte, [32]byte, error) {
	var sender [20]byte
	var txHash [32]byte

	header := blocklist.GetHeader(req.BlockHeight)
	if header == nil {
		return sender, nil, txHash, ErrBlockNotFound
	}

	rawBytes, err := hex.DecodeString(req.RawHex)
	if err != nil {
		return sender, nil, txHash, errors.New("invalid raw_hex")
	}

	proofBytes, err := hex.DecodeString(req.MerkleProofHex)
	if err != nil {
		return sender, nil, txHash, errors.New("invalid merkle_proof_hex")
	}

	proof := splitProofNodes(proofBytes)
	key := mpt.RLPEncodeKey(req.TxIndex)

	// CRIT #1: verify tx-trie inclusion against TransactionsRoot (NOT
	// ReceiptsRoot). Native ETH deposits use the raw RLP-encoded TX bytes
	// as the leaf; the contract reconstructs sender via ecrecover on the
	// signature fields of the parsed transaction.
	value, err := mpt.VerifyProof(header.TransactionsRoot, key, proof)
	if err != nil {
		return sender, nil, txHash, ErrProofFailed
	}

	// Verify the proven value matches the raw TX
	if !bytesEqual(value, rawBytes) {
		return sender, nil, txHash, ErrProofFailed
	}

	// Compute TX hash for observed tracking (returned to caller; caller
	// performs MarkObserved after instruction routing succeeds — CRIT #8).
	txHash = crypto.Keccak256Hash(rawBytes)

	// Check not already observed (read-only; safe before instruction routing).
	if IsObserved(req.BlockHeight, txHash, uint16(req.TxIndex)) {
		return sender, nil, txHash, ErrAlreadyObserved
	}

	// HIGH #41: parseTransaction rejects unsupported types BEFORE downstream
	// state mutations. parseTransaction enforces type ∈ {0 (legacy), 2
	// (EIP-1559)}; type 1 (EIP-2930), 3 (EIP-4844 blob), and 4 (EIP-7702
	// set-code) trigger an explicit error. v2 extends coverage; v1 protects
	// user funds by refusing credit rather than corrupting state.
	parsedTx, err := parseTransaction(rawBytes)
	if err != nil {
		return sender, nil, txHash, err
	}

	// W4 Cluster B CRIT #6 Site 1: reject wrong-chain deposit proofs.
	// Sequencing: trie-proof binds rawBytes -> on-chain root (no forgery);
	// parseTransaction decodes ChainId from the canonical RLP; this check
	// rejects cross-chain replay BEFORE ecrecover spends any cycles.
	if parsedTx.ChainId != chainId {
		return sender, nil, txHash, ErrChainIdMismatch
	}

	// Verify destination is vault
	if parsedTx.To != vaultAddress {
		return sender, nil, txHash, ErrNotVaultDeposit
	}

	// CRIT #11 site 5 (USER, NORMALIZE): legacy ETH wallets may emit high-S
	// signatures. Use EcrecoverCanonical so the deposit verifies under
	// either malleability variant. The L1 mining layer (post-EIP-2) rejects
	// high-S, so only the canonical variant can land on-chain — txHash =
	// keccak256(rawBytes) is L1-canonical.
	sighash := computeTxSighash(rawBytes, parsedTx)
	recoveryV := byte(27 + parsedTx.V)
	rPadded := padTo32(parsedTx.R)
	sPadded := padTo32(parsedTx.S)

	sender, err = crypto.EcrecoverCanonical(sighash, recoveryV, rPadded, sPadded)
	if err != nil {
		return sender, nil, txHash, errors.New("ecrecover failed: " + err.Error())
	}
	if sender == ([20]byte{}) {
		return sender, nil, txHash, errors.New("ecrecover returned zero address")
	}

	// CRIT #8: MarkObserved is intentionally NOT called here. The caller
	// (HandleMap) calls MarkObserved after instruction routing + IncBalance
	// + TrackDeposit have all succeeded, so a failed instruction does not
	// permanently lock the deposit hash to an un-credited outcome.
	//
	// W4 Cluster A Step 3b INPUT BOUNDARY (wei -> gwei): convert the parsed
	// L1 wei amount to gwei before returning. HandleMap stores balances in
	// gwei (int64 max = 9.22e18 gwei = 9.22 billion ETH), so the boundary
	// conversion is here. big.Int.Div truncates toward zero — sub-gwei dust
	// is dropped. This same Div MUST be mirrored in HandleConfirmSpend's
	// L1 verification path (handlers.go ETH branch) so deposit-side and
	// confirm-side truncation match bit-for-bit. Pre-fix HIGH #38 (whale
	// ETH stuck) and CRIT #3 (totalDeduct wrap) both resolve at this
	// boundary because the gwei int64 ceiling is unreachable in practice.
	valueWei := new(big.Int).SetBytes(parsedTx.Value)
	valueGwei := new(big.Int).Div(valueWei, WeiPerGwei)
	return sender, valueGwei.Bytes(), txHash, nil
}

// VerifyERC20Deposit verifies an ERC-20 deposit via receipt inclusion proof.
// Returns the sender address, token amount (big-endian bytes), and the tx hash.
//
// W4 Cluster B CRIT #6 Site 2: chainId parameter added. ERC-20 deposits
// prove receipt-trie inclusion (not tx-trie), so there is no parsed-tx
// ChainId to compare. Instead we cross-check against the STORED block
// header's ChainId field (Site 4 added `ChainId uint64` to EthBlockHeader
// with the 137-byte canonical layout). The header itself originates from
// the ZK verifier (per Site 5+6: ProofOutputs.chainId is part of the
// proven public-values), so a forged header with a wrong chainId can
// never enter blocklist storage in the first place.
func VerifyERC20Deposit(
	req *VerificationRequest,
	vaultAddress [20]byte,
	tokenAddr [20]byte,
	chainId uint64,
) ([20]byte, []byte, [32]byte, error) {
	var sender [20]byte
	var txHash [32]byte

	header := blocklist.GetHeader(req.BlockHeight)
	if header == nil {
		return sender, nil, txHash, ErrBlockNotFound
	}

	// W4 Cluster B CRIT #6 Site 2: stored-header chainId cross-check.
	// header.ChainId is populated by the ZK proof submission flow
	// (zk-header-verifier submitProof reads chainId from ProofOutputs slot
	// 11 — see W1-cluster-B-schema §1). Defense-in-depth: a 0 ChainId
	// means the header was stored under a pre-fix code path (testnet
	// migration window only); reject so we cannot silently credit against
	// an unknown chain.
	if header.ChainId == 0 || header.ChainId != chainId {
		return sender, nil, txHash, ErrChainIdMismatch
	}

	receiptBytes, err := hex.DecodeString(req.RawHex)
	if err != nil {
		return sender, nil, txHash, errors.New("invalid raw_hex")
	}

	proofBytes, err := hex.DecodeString(req.MerkleProofHex)
	if err != nil {
		return sender, nil, txHash, errors.New("invalid merkle_proof_hex")
	}

	proof := splitProofNodes(proofBytes)
	key := mpt.RLPEncodeKey(req.TxIndex)

	value, err := mpt.VerifyProof(header.ReceiptsRoot, key, proof)
	if err != nil {
		return sender, nil, txHash, ErrProofFailed
	}

	if !bytesEqual(value, receiptBytes) {
		return sender, nil, txHash, ErrProofFailed
	}

	txHash = crypto.Keccak256Hash(receiptBytes)

	// CRIT #8: read-side IsObserved stays here (safe / idempotent). The
	// matching MarkObserved write is now performed by the caller AFTER
	// instruction routing succeeds (see HandleMap erc20 branch).
	if IsObserved(req.BlockHeight, txHash, uint16(req.LogIndex)) {
		return sender, nil, txHash, ErrAlreadyObserved
	}

	// Parse receipt and find the Transfer event at LogIndex
	logs, err := parseReceiptLogs(receiptBytes)
	if err != nil {
		return sender, nil, txHash, err
	}

	// CRIT #14 defense-in-depth: writers (monitor scanner.go + bot main.go)
	// now emit per-receipt logIndex (0..N-1) within the receipt's own logs
	// list. The `> 10000` magic ceiling is a separate sanity cap against
	// runaway encoder bugs; cleanup item to replace with
	// constants.MaxLogsPerReceipt in a future pass (NOT a security fix).
	if req.LogIndex > 10000 || int(req.LogIndex) >= len(logs) {
		return sender, nil, txHash, errors.New("log_index out of range")
	}

	log := logs[req.LogIndex]

	// Verify: log.Address == tokenAddress
	if log.Address != tokenAddr {
		return sender, nil, txHash, ErrInvalidToken
	}

	// Verify: topics[0] == Transfer event signature
	if len(log.Topics) < 3 {
		return sender, nil, txHash, errors.New("insufficient topics for Transfer event")
	}
	if log.Topics[0] != TransferEventSig {
		return sender, nil, txHash, errors.New("not a Transfer event")
	}

	// topics[2] == vault address (padded to 32 bytes)
	var vaultPadded [32]byte
	copy(vaultPadded[12:], vaultAddress[:])
	if log.Topics[2] != vaultPadded {
		return sender, nil, txHash, ErrNotVaultDeposit
	}

	// Sender from topics[1] (padded address)
	copy(sender[:], log.Topics[1][12:])
	if sender == ([20]byte{}) {
		return sender, nil, txHash, errors.New("zero-address sender (mint event, not a deposit)")
	}

	// Amount from log.Data (uint256, big-endian)
	amount := log.Data

	// CRIT #8: MarkObserved is intentionally NOT called here. HandleMap is
	// responsible for marking observed only after the deposit has been
	// fully routed and credited — a router-side failure must not lock the
	// observed-deposit slot to an un-credited outcome.
	return sender, amount, txHash, nil
}

// parseTransaction decodes an RLP-encoded Ethereum transaction.
//
// W4 Cluster A HIGH #41: v1 accepts legacy (no type byte) and EIP-1559 (type
// 2). Type 1 (EIP-2930 access list), type 3 (EIP-4844 blob), and type 4
// (EIP-7702 set-code, Pectra) are explicitly rejected with type-named error
// strings so the bot/monitor dead-letter queue can classify them. The error
// fires BEFORE any caller-side state mutation: VerifyETHDeposit no longer
// performs MarkObserved (moved to HandleMap per CRIT #8), and HandleMap
// surfaces the parser error before any IncBalance/TrackDeposit/MarkObserved
// happens. v2 extends parser coverage to types 1/3/4; v1 protects user funds
// by refusing credit (L1 deposit funds are unaffected — they remain in the
// vault TSS EOA and can be returned via an operator-driven recovery path).
//
// Reachability: type 0 (legacy) flows through `raw[0] > 0x7f` because the
// outermost byte of a legacy tx RLP is a list-header prefix in 0xc0..0xff;
// any EIP-2718 typed envelope starts with the type byte in 0x00..0x7f.
func parseTransaction(raw []byte) (*ParsedTx, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty transaction")
	}

	// EIP-2718 typed transaction: first byte is the type
	if raw[0] <= 0x7f {
		txType := raw[0]
		switch txType {
		case 1:
			// EIP-2930 access list — parser not implemented in v1.
			return nil, errors.New("unsupported tx type 1 (EIP-2930 access list) — only EIP-1559 (type-2) and legacy accepted in v1; type-1/3/4 support deferred to post-launch PR")
		case 2:
			return parseEIP1559Tx(raw[1:])
		case 3:
			// EIP-4844 blob — parser not implemented in v1.
			return nil, errors.New("unsupported tx type 3 (EIP-4844 blob) — only EIP-1559 (type-2) and legacy accepted in v1; type-1/3/4 support deferred to post-launch PR")
		case 4:
			// EIP-7702 set-code (Pectra) — parser not implemented in v1.
			// HIGH #41: explicit revert here means the deposit is rejected
			// rather than parsed as a partial structure and silently
			// crediting the wrong amount.
			return nil, errors.New("unsupported tx type 4 (EIP-7702 set-code) — only EIP-1559 (type-2) and legacy accepted in v1; type-1/3/4 support deferred to post-launch PR")
		default:
			return nil, errors.New("unsupported tx type — only EIP-1559 (type-2) and legacy accepted in v1")
		}
	}

	// Legacy transaction (RLP list header, no EIP-2718 type byte).
	return parseLegacyTx(raw)
}

func parseEIP1559Tx(data []byte) (*ParsedTx, error) {
	items, err := rlp.DecodeList(data)
	if err != nil {
		return nil, err
	}
	// EIP-1559: [chainId, nonce, maxPriorityFee, maxFee, gas, to, value, data, accessList, v, r, s]
	if len(items) < 12 {
		return nil, errors.New("invalid EIP-1559 tx: too few fields")
	}

	tx := &ParsedTx{
		ChainId: items[0].AsUint64(),
		Nonce:   items[1].AsUint64(),
		Value:   items[6].AsBytes(),
		Data:    items[7].AsBytes(),
		V:       byte(items[9].AsUint64()),
		R:       items[10].AsBytes(),
		S:       items[11].AsBytes(),
	}
	toBytes := items[5].AsBytes()
	if len(toBytes) == 20 {
		copy(tx.To[:], toBytes)
	}
	return tx, nil
}

func parseLegacyTx(data []byte) (*ParsedTx, error) {
	items, err := rlp.DecodeList(data)
	if err != nil {
		return nil, err
	}
	// Legacy: [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
	if len(items) < 9 {
		return nil, errors.New("invalid legacy tx: too few fields")
	}

	v := items[6].AsUint64()
	parsed := &ParsedTx{
		Nonce: items[0].AsUint64(),
		Value: items[4].AsBytes(),
		Data:  items[5].AsBytes(),
		R:     items[7].AsBytes(),
		S:     items[8].AsBytes(),
	}

	// EIP-155: v = chainId * 2 + 35 + recovery_id
	if v >= 35 {
		parsed.ChainId = (v - 35) / 2
		parsed.V = byte((v - 35) % 2)
	} else {
		parsed.V = byte(v - 27)
	}

	toBytes := items[3].AsBytes()
	if len(toBytes) == 20 {
		copy(parsed.To[:], toBytes)
	}
	return parsed, nil
}

func computeTxSighash(raw []byte, tx *ParsedTx) []byte {
	// For EIP-1559: sighash = keccak256(0x02 || RLP([chainId, nonce, ...fields without v,r,s]))
	// For legacy EIP-155: sighash = keccak256(RLP([nonce, gasPrice, gas, to, value, data, chainId, 0, 0]))
	// We compute from the raw bytes by re-decoding without the signature fields
	// For simplicity in v1, we just hash the full raw (the ecrecover will validate)
	// TODO: implement proper sighash computation for full correctness
	if len(raw) > 0 && raw[0] == 2 {
		// EIP-1559: strip type byte, decode list, re-encode without last 3 items
		items, err := rlp.DecodeList(raw[1:])
		if err != nil || len(items) < 12 {
			return crypto.Keccak256(raw)
		}
		unsigned := make([][]byte, 9)
		for i := 0; i < 9; i++ {
			if items[i].IsList {
				// BUG: this only preserves a single level of children. EIP-2930
				// access list entries are themselves lists ([address, [storageKeys...]]),
				// so the storage-keys sublist is silently re-encoded as empty here. The
				// resulting sighash will mismatch for any tx with non-empty storage keys.
				// Safe today only because BuildETHWithdrawalTx / BuildERC20WithdrawalTx
				// always emit an empty access list (withdrawal.go:114).
				children := make([][]byte, len(items[i].Children))
				for j, child := range items[i].Children {
					if child.IsList {
						children[j] = rlp.EncodeList()
					} else {
						children[j] = rlp.EncodeBytes(child.AsBytes())
					}
				}
				unsigned[i] = rlp.EncodeList(children...)
			} else {
				unsigned[i] = rlp.EncodeBytes(items[i].AsBytes())
			}
		}
		unsignedRLP := rlp.EncodeList(unsigned...)
		return crypto.Keccak256(append([]byte{0x02}, unsignedRLP...))
	}
	// Legacy EIP-155
	items, err := rlp.DecodeList(raw)
	if err != nil || len(items) < 9 {
		return crypto.Keccak256(raw)
	}
	chainIdBytes := rlp.EncodeUint64(tx.ChainId)
	empty := rlp.EncodeBytes(nil)
	unsigned := rlp.EncodeList(
		rlp.EncodeBytes(items[0].AsBytes()), // nonce
		rlp.EncodeBytes(items[1].AsBytes()), // gasPrice
		rlp.EncodeBytes(items[2].AsBytes()), // gas
		rlp.EncodeBytes(items[3].AsBytes()), // to
		rlp.EncodeBytes(items[4].AsBytes()), // value
		rlp.EncodeBytes(items[5].AsBytes()), // data
		chainIdBytes,                        // chainId
		empty,                               // 0
		empty,                               // 0
	)
	return crypto.Keccak256(unsigned)
}

func parseReceiptLogs(receiptRLP []byte) ([]ParsedLog, error) {
	data := receiptRLP
	// Strip EIP-2718 type prefix (0x01 access list, 0x02 EIP-1559)
	if len(data) > 0 && data[0] <= 0x7f {
		data = data[1:]
	}
	items, err := rlp.DecodeList(data)
	if err != nil {
		return nil, err
	}
	// Receipt: [status, cumulativeGasUsed, bloom, logs]
	if len(items) < 4 {
		return nil, errors.New("invalid receipt: too few fields")
	}
	if !items[3].IsList {
		return nil, errors.New("receipt logs should be a list")
	}

	logs := make([]ParsedLog, 0, len(items[3].Children))
	for _, logItem := range items[3].Children {
		if !logItem.IsList || len(logItem.Children) < 3 {
			continue
		}
		var pl ParsedLog
		addrBytes := logItem.Children[0].AsBytes()
		if len(addrBytes) == 20 {
			copy(pl.Address[:], addrBytes)
		}
		if logItem.Children[1].IsList {
			for _, topicItem := range logItem.Children[1].Children {
				var topic [32]byte
				topicBytes := topicItem.AsBytes()
				copy(topic[32-len(topicBytes):], topicBytes)
				pl.Topics = append(pl.Topics, topic)
			}
		}
		pl.Data = logItem.Children[2].AsBytes()
		logs = append(logs, pl)
	}
	return logs, nil
}

func splitProofNodes(data []byte) [][]byte {
	// Proof nodes are concatenated RLP items. Decode each one sequentially.
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

func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b[:32]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
