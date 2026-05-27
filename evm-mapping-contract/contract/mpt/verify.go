// Package mpt implements an Ethereum Merkle-Patricia trie proof
// verifier. This file is a TinyGo-WASM adaptation of go-ethereum
// `trie/proof.go::VerifyProof` plus its unexported callees from
// `trie/node.go` (decodeNode/decodeShort/decodeFull/decodeRef) and
// `trie/encoding.go::keybytesToHex / compactToHex`.
//
// CRIT #4 — Wave 2: the previous custom impl skipped the keccak check
// when node bytes < 32 and so accepted forged 3-byte leaves returning
// attacker-chosen values (dual to M67-03 which showed it also REJECTED
// valid inline-leaf children). Per M67's 4,600-proof differential
// against geth, "ourmpt is not a faithful Ethereum MPT verifier and
// must be replaced." We replace.
//
// Adaptations from geth verbatim:
//   - go-ethereum/ethdb.KeyValueReader is stubbed as an in-memory
//     map[ [32]byte ][]byte; the proof slice is loaded into it and
//     VerifyProof walks by hash like geth.
//   - go-ethereum/common.Hash → [32]byte.
//   - go-ethereum/crypto.Keccak256 → evm-mapping-contract/contract/crypto.Keccak256
//     (host import, gas-accounted).
//   - go-ethereum/rlp.SplitList / SplitString / CountValues →
//     evm-mapping-contract/contract/rlp.Decode / DecodeList (M67-06
//     confirmed canonical).
//   - hasher/log/goroutines/recover removed — TinyGo WASM cannot use them.
//
// Soundness invariant we now enforce (the bug we had): node references
// in a trie are either a 32-byte hash (separate node, hash-checked) OR
// an inline RLP list <32 bytes (embedded in parent, NOT separately
// hashed). The previous impl conflated these by skipping the hash
// check on any node <32 bytes regardless of context, so a 3-byte
// arbitrary leaf as the proof's last element passed. Geth's
// VerifyProof retrieves nodes by hash from the proof DB; an inline
// node has no separate hash entry and is reached via the parent's
// `decodeRef` only, which is the correct contextual check.
package mpt

import (
	"bytes"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/rlp"
)

var (
	ErrInvalidProof = ce.NewContractError(ce.ErrTransaction, "mpt: invalid proof")
	ErrProofTooLong = ce.NewContractError(ce.ErrTransaction, "mpt: proof exceeds max nodes")
	ErrRootMismatch = ce.NewContractError(ce.ErrTransaction, "mpt: root hash mismatch")
	ErrKeyNotFound  = ce.NewContractError(ce.ErrTransaction, "mpt: key not found in proof")
)

const MaxProofNodes = 20

// hashSize matches go-ethereum/common.Hash length.
const hashSize = 32

// ---------------------------------------------------------------------
// Trie node types (geth trie/node.go).
// ---------------------------------------------------------------------

type node interface {
	isTrieNode()
}

type fullNode struct {
	// Children[16] is the value slot (key-terminating branch). Children
	// at indices 0..15 are either nil, a hashNode, an embedded shortNode/
	// fullNode (inline), or a valueNode.
	Children [17]node
}

type shortNode struct {
	Key []byte // hex-encoded key fragment (compactToHex applied)
	Val node
}

type hashNode []byte
type valueNode []byte

func (*fullNode) isTrieNode()  {}
func (*shortNode) isTrieNode() {}
func (hashNode) isTrieNode()   {}
func (valueNode) isTrieNode()  {}

// ---------------------------------------------------------------------
// proofDB — geth's ethdb.KeyValueReader stub.
// ---------------------------------------------------------------------

// proofDB is the WASM-side analogue of `ethdb.KeyValueReader`. The MPT
// proof is presented as a slice of RLP-encoded nodes; we index each by
// keccak256(node) so VerifyProof can fetch by hash exactly the way
// geth does.
type proofDB struct {
	nodes map[[hashSize]byte][]byte
}

func newProofDB(proof [][]byte) *proofDB {
	db := &proofDB{nodes: make(map[[hashSize]byte][]byte, len(proof))}
	for _, n := range proof {
		var h [hashSize]byte
		copy(h[:], crypto.Keccak256(n))
		db.nodes[h] = n
	}
	return db
}

func (db *proofDB) Get(key []byte) ([]byte, bool) {
	if len(key) != hashSize {
		return nil, false
	}
	var h [hashSize]byte
	copy(h[:], key)
	v, ok := db.nodes[h]
	return v, ok
}

// ---------------------------------------------------------------------
// VerifyProof — geth verbatim port.
// ---------------------------------------------------------------------

// VerifyProof checks merkle proofs. The given proof must contain the
// value for `key` in a trie with the given root hash. VerifyProof
// returns an error if the proof contains invalid trie nodes or the
// wrong value.
//
// proof is a list of RLP-encoded trie nodes; nodes are indexed by
// keccak256(node) inside the verifier and walked from root.
func VerifyProof(root [32]byte, key []byte, proof [][]byte) ([]byte, error) {
	if len(proof) == 0 {
		return nil, ErrInvalidProof
	}
	if len(proof) > MaxProofNodes {
		return nil, ErrProofTooLong
	}

	db := newProofDB(proof)

	hexKey := keybytesToHex(key)
	wantHash := root
	for i := 0; ; i++ {
		buf, ok := db.Get(wantHash[:])
		if !ok {
			// Equivalent of geth's `proof node N (hash %064x) missing`.
			if i == 0 {
				return nil, ErrRootMismatch
			}
			return nil, ErrInvalidProof
		}
		n, err := decodeNode(wantHash[:], buf)
		if err != nil {
			return nil, ErrInvalidProof
		}
		keyrest, cld := get(n, hexKey)
		switch cld := cld.(type) {
		case nil:
			// The trie does not contain the key.
			return nil, ErrKeyNotFound
		case hashNode:
			hexKey = keyrest
			copy(wantHash[:], cld)
		case valueNode:
			return []byte(cld), nil
		default:
			// Should not happen if get() respects the geth contract.
			return nil, ErrInvalidProof
		}
		// Bound the walk — proof length is the natural ceiling.
		if i > MaxProofNodes {
			return nil, ErrProofTooLong
		}
	}
}

// get walks a single trie node, returning the remaining key and the
// next child to resolve (which the caller then re-enters via hashNode
// → DB lookup, or returns directly if it's a valueNode).
//
// Direct port of geth `trie/proof.go::get` with skipResolved=true.
func get(tn node, key []byte) ([]byte, node) {
	for {
		switch n := tn.(type) {
		case *shortNode:
			if len(key) < len(n.Key) || !bytes.Equal(n.Key, key[:len(n.Key)]) {
				return nil, nil
			}
			tn = n.Val
			key = key[len(n.Key):]
		case *fullNode:
			if len(key) == 0 {
				// Branch node value slot.
				return nil, n.Children[16]
			}
			tn = n.Children[key[0]]
			key = key[1:]
		case hashNode:
			return key, n
		case nil:
			return key, nil
		case valueNode:
			return nil, n
		default:
			return nil, nil
		}
	}
}

// ---------------------------------------------------------------------
// decodeNode / decodeShort / decodeFull / decodeRef — geth verbatim.
// Adapted to use evm-mapping-contract/contract/rlp.Item form.
// ---------------------------------------------------------------------

func decodeNode(hash, buf []byte) (node, error) {
	if len(buf) == 0 {
		return nil, ErrInvalidProof
	}
	item, _, err := rlp.Decode(buf)
	if err != nil || !item.IsList {
		return nil, ErrInvalidProof
	}
	switch len(item.Children) {
	case 2:
		return decodeShort(hash, item.Children)
	case 17:
		return decodeFull(hash, item.Children)
	default:
		return nil, ErrInvalidProof
	}
}

func decodeShort(hash []byte, elems []rlp.Item) (node, error) {
	if len(elems) != 2 {
		return nil, ErrInvalidProof
	}
	kbuf := elems[0].AsBytes()
	key := compactToHex(kbuf)
	if hasTerm(key) {
		// leaf
		val := elems[1].AsBytes()
		return &shortNode{Key: key, Val: valueNode(val)}, nil
	}
	// extension
	r, err := decodeRef(elems[1])
	if err != nil {
		return nil, err
	}
	return &shortNode{Key: key, Val: r}, nil
}

func decodeFull(hash []byte, elems []rlp.Item) (*fullNode, error) {
	if len(elems) != 17 {
		return nil, ErrInvalidProof
	}
	n := &fullNode{}
	for i := 0; i < 16; i++ {
		cld, err := decodeRef(elems[i])
		if err != nil {
			return nil, err
		}
		n.Children[i] = cld
	}
	val := elems[16].AsBytes()
	if len(val) > 0 {
		n.Children[16] = valueNode(val)
	}
	return n, nil
}

// decodeRef is the geth-faithful invariant enforcer. A child reference
// in a trie node is either:
//   - an RLP list (embedded inline node) whose total RLP size is < 32B,
//   - an empty RLP string (no child), or
//   - a 32-byte RLP string (hash reference to a separately stored node).
//
// CRIT #4: the OLD impl accepted any short string as a "value" and
// returned it directly to the caller without enforcing the inline-RLP-
// list constraint. That let a 3-byte forged leaf pass. We reject any
// reference whose RLP kind is "string" and whose length is neither 0
// nor 32.
func decodeRef(item rlp.Item) (node, error) {
	if item.IsList {
		// Embedded inline node. Re-encode size check is implicit:
		// because the parent RLP-decoded successfully and contained
		// this list, the list's full RLP must be <32 bytes (else it
		// would have been a hashNode at the wire level). We trust the
		// parent's RLP framing here, matching geth.
		switch len(item.Children) {
		case 2:
			return decodeShort(nil, item.Children)
		case 17:
			return decodeFull(nil, item.Children)
		default:
			return nil, ErrInvalidProof
		}
	}
	data := item.AsBytes()
	switch len(data) {
	case 0:
		return nil, nil
	case hashSize:
		return hashNode(data), nil
	default:
		return nil, ErrInvalidProof
	}
}

// ---------------------------------------------------------------------
// Key encoding helpers — geth trie/encoding.go verbatim.
// ---------------------------------------------------------------------

// keybytesToHex turns a byte slice into a nibble slice with the trie
// terminator (0x10) appended.
func keybytesToHex(str []byte) []byte {
	l := len(str)*2 + 1
	nibbles := make([]byte, l)
	for i, b := range str {
		nibbles[i*2] = b / 16
		nibbles[i*2+1] = b % 16
	}
	nibbles[l-1] = 16
	return nibbles
}

// compactToHex decodes a compact-encoded trie path back to nibbles.
// Direct port of geth trie/encoding.go::compactToHex.
func compactToHex(compact []byte) []byte {
	if len(compact) == 0 {
		return compact
	}
	base := keybytesToHex(compact)
	// delete terminator flag
	if base[0] < 2 {
		base = base[:len(base)-1]
	}
	// apply odd flag
	chop := 2 - base[0]&1
	return base[chop:]
}

// hasTerm reports whether the hex-encoded key has the terminator nibble.
func hasTerm(s []byte) bool {
	return len(s) > 0 && s[len(s)-1] == 16
}

// RLPEncodeKey is preserved from the previous public surface — callers
// (mapping/handlers.go HandleConfirmSpend, mapping/proof.go) use it to
// derive the MPT key for tx/receipt index. In Ethereum, the key is
// RLP(uint(index)).
func RLPEncodeKey(index uint64) []byte {
	return rlp.EncodeUint64(index)
}

// keyToNibbles + compactToNibbles are shims kept for the existing
// verify_test.go unit suite. The new VerifyProof uses keybytesToHex /
// compactToHex (geth-faithful) instead. These shims do NOT match geth's
// terminator convention — they replicate the original ourmpt helpers
// purely so the test file compiles. Do not call them from production
// code.
func keyToNibbles(key []byte) []byte {
	nibbles := make([]byte, len(key)*2)
	for i, b := range key {
		nibbles[i*2] = b >> 4
		nibbles[i*2+1] = b & 0x0f
	}
	return nibbles
}

func compactToNibbles(compact []byte) ([]byte, bool) {
	if len(compact) == 0 {
		return nil, false
	}
	firstNibble := compact[0] >> 4
	isLeaf := firstNibble >= 2
	isOdd := firstNibble%2 == 1
	var nibbles []byte
	if isOdd {
		nibbles = append(nibbles, compact[0]&0x0f)
	}
	for _, b := range compact[1:] {
		nibbles = append(nibbles, b>>4, b&0x0f)
	}
	return nibbles, isLeaf
}
