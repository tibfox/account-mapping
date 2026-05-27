package mapping

type MapParams struct {
	TxData       VerificationRequest `json:"tx_data"`
	Instructions []string            `json:"instructions"`
}

type VerificationRequest struct {
	BlockHeight    uint64 `json:"block_height"`
	TxIndex        uint64 `json:"tx_index"`
	RawHex         string `json:"raw_hex"`
	MerkleProofHex string `json:"merkle_proof_hex"`
	LogIndex       uint64 `json:"log_index"`
	TokenAddress   string `json:"token_address"`
	DepositType    string `json:"deposit_type"` // "eth" or "erc20"
}

type TransferParams struct {
	Amount       string `json:"amount"`
	To           string `json:"to"`
	From         string `json:"from"`
	Asset        string `json:"asset"`
	TokenAddress string `json:"token_address"`
	DeductFee    bool   `json:"deduct_fee"`
	MaxFee       string `json:"max_fee"`
}

type AllowanceParams struct {
	Spender string `json:"spender"`
	Amount  string `json:"amount"`
	Asset   string `json:"asset"`
}

type RegisterTokenParams struct {
	Address       string `json:"address"`
	Symbol        string `json:"symbol"`
	Decimals      uint8  `json:"decimals"`
	MinWithdrawal int64  `json:"min_withdrawal"`
}

type TokenInfo struct {
	Symbol        string `json:"symbol"`
	Decimals      uint8  `json:"decimals"`
	MinWithdrawal int64  `json:"min_withdrawal"`
}

// ConfirmSpendRequest carries both tx and receipt proofs for withdrawal
// confirmation. W4 Cluster E CRIT #5 + HIGH #13 (D-E-1 + D-E-2 LOCKED): the
// payload is 10 TOP-LEVEL fields — 6 proof legs + 4 intent reference fields.
// Adding the intent fields lets the contract verify the TSS-signed L1 tx
// matches the on-chain PendingSpend (closes HIGH #13: TSS quorum can sign
// arbitrary L1 tx). Validation order in HandleConfirmSpend per D-E-2:
//  1. Entry-point intent binding (all 4 IntentX must equal PendingSpend)
//  2. recoveredSender == ps.VaultAtQueue (snapshotted vault from Cluster F)
//  3. parsedTx.To / parsedTx.Value / asset binding (defense-in-depth)
// Wire-format authority: `confirmSpendSchema()` wasmexport in main.go
// returns this struct's canonical schema JSON for bot startup introspection.
type ConfirmSpendRequest struct {
	// Proof legs (6 existing)
	BlockHeight     uint64 `json:"block_height"`
	TxIndex         uint64 `json:"tx_index"`
	TxHex           string `json:"tx_hex"`
	TxProofHex      string `json:"tx_proof_hex"`
	ReceiptHex      string `json:"receipt_hex"`
	ReceiptProofHex string `json:"receipt_proof_hex"`
	// Intent reference (4 NEW — HIGH #13 D-E-1). Contract MUST verify all 4
	// match the looked-up PendingSpend BEFORE proof verification.
	IntentNonce  uint64 `json:"intent_nonce"`  // PendingSpend.Nonce
	IntentTo     string `json:"intent_to"`     // PendingSpend.To
	IntentAmount int64  `json:"intent_amount"` // PendingSpend.Amount (int64 per D-E-0 v22)
	IntentAsset  string `json:"intent_asset"`  // PendingSpend.Asset
}

// L1ProofOfDrop — W4 Cluster E CRIT #26 + CRIT #27 (D-E-4 LOCKED). One of
// TWO proof shapes is accepted; bot supplies whichever it can construct:
//
//  - Type A "reverted-receipt": receipt-trie MPT proof showing the L1 tx
//    at the cleared/expired nonce was mined with `status=0` (reverted).
//    Reuses the receipt-trie infrastructure from HandleConfirmSpend
//    (CRIT #1).
//
//  - Type B "block-inclusion-without-tx": prove that block at FinalizedHeight
//    is finalized AND does NOT contain a tx at TxIndex matching the
//    expired nonce. Requires a transactions-trie proof PLUS a finality
//    attestation (encoded as the ZK-verified block header read via
//    blocklist.GetHeader; the L1 finality is anchored by the SP1 Helios
//    Groth16 light client — the ZK architecture note above is the trust
//    root, NOT an external RPC).
//
// LOCKED wire format (this manifest — closes the W1 deferral flagged in
// MILO-REVIEW §1 Cluster E CONCERNS):
//
//	{
//	  "type":              "reverted_receipt" | "block_inclusion_without_tx",
//	  "block_height":      uint64,            // finalized L1 height of the proof
//	  "tx_index":          uint64,            // tx index for type A; expected slot for type B
//	  "tx_nonce":          uint64,            // L1 nonce being proven cleared (== ps.Nonce)
//	  // Type A only — empty for type B
//	  "receipt_hex":       "0x...",           // RLP receipt with status=0
//	  "receipt_proof_hex": "0x...",           // concatenated receipt-trie MPT nodes
//	  // Type B only — empty for type A
//	  "tx_at_index_hex":   "0x...",           // RLP of whatever tx IS at tx_index in this block
//	  "tx_proof_hex":      "0x...",           // tx-trie MPT proof for that tx
//	  // Optional — Type B can include this when the bot wants to prove the
//	  // vault's L1 account nonce has ALREADY advanced past tx_nonce as an
//	  // additional safety hint (verified opportunistically).
//	  "vault_nonce_proof_hex": "0x..."
//	}
//
// Verification path (mirrors HandleConfirmSpend's MPT verify):
//  - Type A: blocklist.GetHeader(BlockHeight) → header.ReceiptsRoot →
//    mpt.VerifyProof(rcptRoot, rlp(TxIndex), proofNodes) → receipt.Status == 0
//    AND receipt's parsed nonce field MUST equal TxNonce. Reject otherwise.
//  - Type B: blocklist.GetHeader(BlockHeight) → header.TransactionsRoot →
//    mpt.VerifyProof(txRoot, rlp(TxIndex), proofNodes) → parseTransaction(...)
//    → parsed.Nonce > TxNonce  (i.e. the slot is occupied by a HIGHER nonce
//    from the same vault, which proves the original tx at TxNonce was
//    dropped/replaced and the gap is closed). If TxIndex slot is empty
//    (proof returns nil), reject — bot must use Type A in that case.
//
// Mainnet/testnet posture: both types require a header already anchored
// via the ZK light client (per the ZK architecture note above). The bot
// MUST NOT supply a header that has not been ingested by HandleAddBlocks.
type L1ProofOfDrop struct {
	Type                string `json:"type"`                  // "reverted_receipt" or "block_inclusion_without_tx"
	BlockHeight         uint64 `json:"block_height"`          // finalized L1 height
	TxIndex             uint64 `json:"tx_index"`              // index within block
	TxNonce             uint64 `json:"tx_nonce"`              // L1 nonce being cleared
	ReceiptHex          string `json:"receipt_hex,omitempty"` // type A
	ReceiptProofHex     string `json:"receipt_proof_hex,omitempty"`
	TxAtIndexHex        string `json:"tx_at_index_hex,omitempty"` // type B
	TxProofHex          string `json:"tx_proof_hex,omitempty"`
	VaultNonceProofHex  string `json:"vault_nonce_proof_hex,omitempty"` // optional safety hint (type B)
}

// L1ProofTypeRevertedReceipt / L1ProofTypeBlockInclusion — canonical type
// strings. Implementing handlers compare against these constants; do NOT
// inline string literals.
const (
	L1ProofTypeRevertedReceipt = "reverted_receipt"
	L1ProofTypeBlockInclusion  = "block_inclusion_without_tx"
)

// W4 Cluster E payload structs for the new wasmexports. The handler-side
// JSON unmarshal sites are in main.go; payload shape is part of the wire
// contract surfaced via confirmSpendSchema-style introspection (lifecycle
// payloads do NOT have their own introspection export — the proof shape
// is documented in this file and via the W1/W4 manifests).

// ClearNonceParams — W4 Cluster E B-E-4 + S-E-v17-2 (clearNonce wasmexport
// shape change). Pre-fix wasmexport ignored its input with `_ *string`,
// making the proof unreachable. Post-fix takes this struct via the
// propose/execute payload bytes.
type ClearNonceParams struct {
	Proof L1ProofOfDrop `json:"proof"`
}

// ExpireWithdrawalParams — W4 Cluster E CRIT #26 (D-E-3). Nonce names the
// confirmed-head withdrawal to expire; proof is REQUIRED for early-cancel
// by original withdrawer, OPTIONAL for post-window expiry.
type ExpireWithdrawalParams struct {
	Nonce uint64        `json:"nonce"`
	Proof L1ProofOfDrop `json:"proof"`
}

// CancelMyWithdrawalParams — W4 Cluster E CRIT #26 companion. Proof
// MANDATORY (must NOT race in-flight L1 tx confirmation).
type CancelMyWithdrawalParams struct {
	Nonce uint64        `json:"nonce"`
	Proof L1ProofOfDrop `json:"proof"`
}

// Parsed EIP-1559 transaction fields
type ParsedTx struct {
	ChainId  uint64
	Nonce    uint64
	To       [20]byte
	Value    []byte // big-endian uint256
	Data     []byte
	V        byte
	R        []byte
	S        []byte
}

// DexInstruction for swap routing
type DexInstruction struct {
	Type             string `json:"type"`
	Version          string `json:"version"`
	AssetIn          string `json:"asset_in"`
	AmountIn         string `json:"amount_in"`
	AssetOut         string `json:"asset_out"`
	Recipient        string `json:"recipient"`
	DestinationChain string `json:"destination_chain"`
}

// Parsed receipt log
type ParsedLog struct {
	Address [20]byte
	Topics  [][32]byte
	Data    []byte
}
