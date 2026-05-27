package blocklist

import (
	"encoding/hex"
	"errors"
	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/sdk"
	"strconv"
)

// EthBlockHeader — W4 Cluster B CRIT #6 Site 4 (LOCKED W1 §AH + W1 §BL):
//   - Added `ChainId uint64` field (appended at the END, after Timestamp).
//   - Added 1-byte version prefix at offset 0 (Sonnet v10 S6 future-upgrade
//     warning closure). The current version is byte 1.
//   - Final canonical layout: [version:1] + [existing 128 bytes byte-for-byte]
//   - [chainId:8 big-endian] = 137 bytes total.
//   - Append-last is REQUIRED — inserting chainId before Timestamp would
//     shift existing byte offsets and break any decoder that reads the
//     128-byte legacy layout.
//
// CRIT #29 v9 verdict: the version byte is defense-in-depth. A future
// schema change can bump it and DeserializeHeader can branch on version
// rather than silently misreading. v1 is the only valid version today;
// reads of any other version are rejected.
//
// Cluster B Site 4 + W4 Cluster A flow: the L2 ETH deposit verifier uses
// ChainId for the receipt-trie path (no parsed-tx ChainId available);
// the value comes from the ZK proof (Site 5/6 -> stored via submitProof
// in zk-header-verifier -> read here via blocklist.GetHeader). On the
// account-mapping side, the addBlocks legacy oracle path also gains a
// ChainId column (operator-supplied per Hive transaction) as a backward
// path during the ZK ramp-up window; the field is still validated against
// the contract's configured chainId BEFORE storing.
type EthBlockHeader struct {
	BlockNumber      uint64
	StateRoot        [32]byte
	TransactionsRoot [32]byte
	ReceiptsRoot     [32]byte
	BaseFeePerGas    uint64
	GasLimit         uint64
	Timestamp        uint64
	ChainId          uint64
}

// HeaderVersionV1 — W4 Cluster B Site 4 + CRIT #29 v9 verdict:
// the on-chain serialized header gains a 1-byte version prefix. v1 is
// the only valid version today; future schema changes bump this and
// DeserializeHeader branches on it.
const HeaderVersionV1 byte = 0x01

// HeaderSerializedSize — LOCKED 137 bytes:
//
//	version(1) + blockNumber(8) + stateRoot(32) + txRoot(32) + rcptRoot(32)
//	+ baseFee(8) + gasLimit(8) + timestamp(8) + chainId(8) = 137.
const HeaderSerializedSize = 137

func (h *EthBlockHeader) Serialize() string {
	buf := make([]byte, 0, HeaderSerializedSize)
	// Version byte (offset 0)
	buf = append(buf, HeaderVersionV1)
	// Legacy 128-byte body (offsets 1-128, BYTE-FOR-BYTE unchanged)
	buf = appendUint64(buf, h.BlockNumber)
	buf = append(buf, h.StateRoot[:]...)
	buf = append(buf, h.TransactionsRoot[:]...)
	buf = append(buf, h.ReceiptsRoot[:]...)
	buf = appendUint64(buf, h.BaseFeePerGas)
	buf = appendUint64(buf, h.GasLimit)
	buf = appendUint64(buf, h.Timestamp)
	// W4 Cluster B Site 4: appended chainId (offsets 129-136, big-endian)
	buf = appendUint64(buf, h.ChainId)
	return string(buf)
}

// DeserializeHeader — W4 Cluster B Site 4 + §BL LOCKED:
// length guard uses `< HeaderSerializedSize` (i.e. reject-if-shorter-than-137),
// NOT `!= 137`. Using `!=` would silently reject any future forward-compat
// padding; `<` accepts any buffer with at least the full 137 bytes.
func DeserializeHeader(data string) (*EthBlockHeader, error) {
	buf := []byte(data)
	if len(buf) < HeaderSerializedSize {
		return nil, ce.NewContractError(
			ce.ErrInput,
			"header data too short (expected at least 137 bytes after version prefix)",
		)
	}
	// Version byte gate.
	if buf[0] != HeaderVersionV1 {
		return nil, ce.NewContractError(ce.ErrInput, "header version unsupported")
	}
	h := &EthBlockHeader{}
	offset := 1 // skip version byte
	h.BlockNumber = readUint64(buf, &offset)
	copy(h.StateRoot[:], buf[offset:offset+32])
	offset += 32
	copy(h.TransactionsRoot[:], buf[offset:offset+32])
	offset += 32
	copy(h.ReceiptsRoot[:], buf[offset:offset+32])
	offset += 32
	h.BaseFeePerGas = readUint64(buf, &offset)
	h.GasLimit = readUint64(buf, &offset)
	h.Timestamp = readUint64(buf, &offset)
	// W4 Cluster B Site 4: chainId at byte offset 129-136
	h.ChainId = readUint64(buf, &offset)
	return h, nil
}

func StoreHeader(header EthBlockHeader) {
	key := constants.BlockPrefix + strconv.FormatUint(header.BlockNumber, 10)
	sdk.StateSetObject(key, header.Serialize())
}

func GetHeader(blockNumber uint64) *EthBlockHeader {
	key := constants.BlockPrefix + strconv.FormatUint(blockNumber, 10)
	data := readState(key)
	if data == nil {
		return nil
	}
	h, err := DeserializeHeader(*data)
	if err != nil {
		return nil
	}
	return h
}

func DeleteHeader(blockNumber uint64) {
	key := constants.BlockPrefix + strconv.FormatUint(blockNumber, 10)
	sdk.StateDeleteObject(key)
}

func GetLastHeight() uint64 {
	data := readState(constants.LastHeightKey)
	if data == nil {
		return 0
	}
	h, err := strconv.ParseUint(*data, 10, 64)
	if err != nil {
		return 0
	}
	return h
}

// readState reads from the ZK verifier contract if configured, otherwise from own state.
// When a verifier contract ID is set, block headers come from the ZK-verified store.
// Falls back to own state for backward compatibility with the oracle BLS path.
func readState(key string) *string {
	vcid := sdk.StateGetObject(constants.VerifierContractIdKey)
	if vcid != nil && *vcid != "" {
		result := sdk.ContractStateGet(*vcid, key)
		if result == nil || *result == "" {
			return nil
		}
		return result
	}
	return sdk.StateGetObject(key)
}

func SetLastHeight(height uint64) {
	sdk.StateSetObject(constants.LastHeightKey, strconv.FormatUint(height, 10))
}

type AddBlocksParams struct {
	Blocks    []AddBlockEntry `json:"blocks"`
	LatestFee uint64          `json:"latest_fee"`
}

// AddBlockEntry — W4 Cluster B CRIT #6 Site 4 (legacy-oracle-path schema):
// extended with `ChainId` so the operator-fed addBlocks/replaceBlock calls
// (kept during the ZK verifier ramp-up window) can populate the new field.
// In steady state, headers come from the ZK verifier (no AddBlockEntry path
// involved); during the ramp-up window, the operator MUST supply chainId
// matching the contract's configured chainId() — HandleAddBlocks validates
// this before any StoreHeader, so a mismatched-chain operator submission
// is rejected at ingestion (defense-in-depth in case the operator wires
// the wrong ETH RPC).
type AddBlockEntry struct {
	BlockNumber      uint64 `json:"block_number"`
	StateRoot        string `json:"state_root"`
	TransactionsRoot string `json:"transactions_root"`
	ReceiptsRoot     string `json:"receipts_root"`
	BaseFeePerGas    uint64 `json:"base_fee_per_gas"`
	GasLimit         uint64 `json:"gas_limit"`
	Timestamp        uint64 `json:"timestamp"`
	ChainId          uint64 `json:"chain_id"`
}

// HandleAddBlocks — W4 Cluster B Site 4: chainId now populates the
// EthBlockHeader.ChainId field on every stored header. Caller (main.go's
// addBlocks wasmexport) must pass the contract's configured chainId so
// HandleAddBlocks can validate `entry.ChainId == expectedChainId` before
// any StoreHeader. Pre-fix, headers stored under the legacy oracle path
// had no chainId binding; an operator wiring the wrong RPC would silently
// populate the bridge with cross-chain headers.
func HandleAddBlocks(params *AddBlocksParams, expectedChainId uint64) error {
	lastHeight := GetLastHeight()

	if lastHeight == 0 {
		return ce.NewContractError(ce.ErrInitialization, "contract not seeded: call seedBlocks first")
	}

	for _, entry := range params.Blocks {
		if entry.BlockNumber != lastHeight+1 {
			return ce.NewContractError(ce.ErrInput, "block heights must be sequential")
		}

		// W4 Cluster B Site 4: chainId guard. Reject any entry whose chainId
		// does not match the contract's expected chainId. expectedChainId=0
		// (uninitialized) is also a reject — the contract MUST be configured
		// before legacy-oracle blocks can be ingested.
		if expectedChainId == 0 {
			return errors.New("contract chainId not configured; cannot ingest headers")
		}
		if entry.ChainId != expectedChainId {
			return errors.New("entry chain_id does not match contract chain_id")
		}

		stateRoot, err := hexTo32(entry.StateRoot)
		if err != nil {
			return ce.WrapContractError(ce.ErrInvalidHex, err, "state_root")
		}
		txRoot, err := hexTo32(entry.TransactionsRoot)
		if err != nil {
			return ce.WrapContractError(ce.ErrInvalidHex, err, "transactions_root")
		}
		rcptRoot, err := hexTo32(entry.ReceiptsRoot)
		if err != nil {
			return ce.WrapContractError(ce.ErrInvalidHex, err, "receipts_root")
		}

		header := EthBlockHeader{
			BlockNumber:      entry.BlockNumber,
			StateRoot:        stateRoot,
			TransactionsRoot: txRoot,
			ReceiptsRoot:     rcptRoot,
			BaseFeePerGas:    entry.BaseFeePerGas,
			GasLimit:         entry.GasLimit,
			Timestamp:        entry.Timestamp,
			ChainId:          entry.ChainId,
		}

		StoreHeader(header)
		lastHeight = entry.BlockNumber

		// Prune old headers
		if entry.BlockNumber > constants.MaxBlockRetention {
			pruneHeight := entry.BlockNumber - constants.MaxBlockRetention
			DeleteHeader(pruneHeight)
		}
	}

	SetLastHeight(lastHeight)
	return nil
}

func hexTo32(s string) ([32]byte, error) {
	var result [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return result, ce.NewContractError(ce.ErrInvalidHex, "invalid 32-byte hex")
	}
	copy(result[:], b)
	return result, nil
}

func appendUint64(buf []byte, v uint64) []byte {
	return append(buf,
		byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v),
	)
}

func readUint64(buf []byte, offset *int) uint64 {
	v := uint64(buf[*offset])<<56 | uint64(buf[*offset+1])<<48 |
		uint64(buf[*offset+2])<<40 | uint64(buf[*offset+3])<<32 |
		uint64(buf[*offset+4])<<24 | uint64(buf[*offset+5])<<16 |
		uint64(buf[*offset+6])<<8 | uint64(buf[*offset+7])
	*offset += 8
	return v
}

// HandleSeedBlock — W4 Cluster B Site 4: chainId is required on seed.
func HandleSeedBlock(entry *AddBlockEntry, expectedChainId uint64) error {
	if entry.BlockNumber == 0 {
		return ce.NewContractError(ce.ErrInput, "seed block_number must be > 0")
	}
	if expectedChainId == 0 {
		return errors.New("contract chainId not configured; cannot seed")
	}
	if entry.ChainId != expectedChainId {
		return errors.New("seed chain_id does not match contract chain_id")
	}
	txRoot, err := hexTo32(entry.TransactionsRoot)
	if err != nil {
		return ce.WrapContractError(ce.ErrInvalidHex, err, "transactions_root")
	}
	rcptRoot, err := hexTo32(entry.ReceiptsRoot)
	if err != nil {
		return ce.WrapContractError(ce.ErrInvalidHex, err, "receipts_root")
	}
	header := EthBlockHeader{
		BlockNumber:      entry.BlockNumber,
		TransactionsRoot: txRoot,
		ReceiptsRoot:     rcptRoot,
		BaseFeePerGas:    entry.BaseFeePerGas,
		GasLimit:         entry.GasLimit,
		Timestamp:        entry.Timestamp,
		ChainId:          entry.ChainId,
	}
	StoreHeader(header)
	SetLastHeight(entry.BlockNumber)
	return nil
}

// HandleReplaceBlock — W4 Cluster B Site 4 + W4 Cluster C HIGH #9 / HIGH #35:
//   - chainId on the replacement entry MUST match the existing stored
//     header's ChainId. Pre-fix, replaceBlock could silently mutate the
//     chainId of an in-place header — replaceBlock is an emergency-only
//     admin operation but a chainId pivot via this path is precisely the
//     CRIT #6 attack class.
//   - Reject if either the existing or the new ChainId is 0 (defense
//     against an unconfigured contract).
//   - HIGH #9 / HIGH #35 (M9/INV-29): after rewriting the header at the
//     target height, delete the observed-list state key for that height.
//     The observed list at `o-{height}` is keyed by (txHash, index) which
//     validated against the OLD ReceiptsRoot. Replacing the header changes
//     ReceiptsRoot, so prior observed entries are now binding against a
//     trie root that the new header no longer commits to. Leaving the
//     entries stale causes one of two bugs:
//     (a) a real deposit at the rewritten height fails with
//     ErrAlreadyObserved against a no-longer-valid prior entry, or
//     (b) the prior observed entry locks in a deposit that the NEW
//     ReceiptsRoot would have rejected as invalid.
//     The observed entries for a block are coalesced under one state key
//     (mapping/observed.go: `o-{height}` -> concatenated 34-byte entries),
//     so a single StateDeleteObject deletes them all. Any subsequent
//     deposit at this height must re-prove against the new header.
//     KeyDiff includes Deletions (host-runtime guarantees the delete is
//     part of the same atomic write set as StoreHeader).
func HandleReplaceBlock(entry *AddBlockEntry, expectedChainId uint64) error {
	existing := GetHeader(entry.BlockNumber)
	if existing == nil {
		return ce.NewContractError(ce.ErrStateAccess, "block not found for replacement")
	}
	if expectedChainId == 0 {
		return errors.New("contract chainId not configured; cannot replace")
	}
	if entry.ChainId != expectedChainId {
		return errors.New("replacement chain_id does not match contract chain_id")
	}
	if existing.ChainId != 0 && existing.ChainId != entry.ChainId {
		return errors.New("replacement chain_id does not match existing header chain_id")
	}

	stateRoot, err := hexTo32(entry.StateRoot)
	if err != nil {
		return ce.WrapContractError(ce.ErrInvalidHex, err, "state_root")
	}
	txRoot, err := hexTo32(entry.TransactionsRoot)
	if err != nil {
		return ce.WrapContractError(ce.ErrInvalidHex, err, "transactions_root")
	}
	rcptRoot, err := hexTo32(entry.ReceiptsRoot)
	if err != nil {
		return ce.WrapContractError(ce.ErrInvalidHex, err, "receipts_root")
	}

	header := EthBlockHeader{
		BlockNumber:      entry.BlockNumber,
		StateRoot:        stateRoot,
		TransactionsRoot: txRoot,
		ReceiptsRoot:     rcptRoot,
		BaseFeePerGas:    entry.BaseFeePerGas,
		GasLimit:         entry.GasLimit,
		Timestamp:        entry.Timestamp,
		ChainId:          entry.ChainId,
	}

	StoreHeader(header)

	// HIGH #9 / HIGH #35: invalidate observed entries at the rewritten
	// height. The key format mirrors mapping/observed.go::observedKey:
	// constants.ObservedBlockPrefix + strconv.FormatUint(height, 10).
	// We construct the key directly here rather than importing the mapping
	// package (blocklist must not depend on mapping — mapping already
	// imports blocklist).
	observedKey := constants.ObservedBlockPrefix + strconv.FormatUint(entry.BlockNumber, 10)
	sdk.StateDeleteObject(observedKey)
	return nil
}
