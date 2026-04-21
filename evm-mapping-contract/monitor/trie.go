package monitor

import (
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/rlp"
)

// trieNode is an interface for MPT nodes used during trie construction.
type trieNode interface {
	hash() []byte
	encode() []byte
}

type leafNode struct {
	keyNibbles []byte
	value      []byte
}

type branchNode struct {
	children [16]trieNode
	value    []byte
}

type extensionNode struct {
	keyNibbles []byte
	child      trieNode
}

func (n *leafNode) encode() []byte {
	compact := nibblesToCompact(n.keyNibbles, true)
	return rlp.EncodeList(rlp.EncodeBytes(compact), rlp.EncodeBytes(n.value))
}

func (n *leafNode) hash() []byte {
	enc := n.encode()
	if len(enc) < 32 {
		return enc
	}
	return crypto.Keccak256(enc)
}

func (n *branchNode) encode() []byte {
	items := make([][]byte, 17)
	for i := 0; i < 16; i++ {
		if n.children[i] == nil {
			items[i] = rlp.EncodeBytes(nil)
		} else {
			childEnc := n.children[i].encode()
			if len(childEnc) < 32 {
				items[i] = childEnc
			} else {
				items[i] = rlp.EncodeBytes(crypto.Keccak256(childEnc))
			}
		}
	}
	items[16] = rlp.EncodeBytes(n.value)
	return rlp.EncodeList(items...)
}

func (n *branchNode) hash() []byte {
	return crypto.Keccak256(n.encode())
}

func (n *extensionNode) encode() []byte {
	compact := nibblesToCompact(n.keyNibbles, false)
	childEnc := n.child.encode()
	var childRef []byte
	if len(childEnc) < 32 {
		childRef = childEnc
	} else {
		childRef = rlp.EncodeBytes(crypto.Keccak256(childEnc))
	}
	return rlp.EncodeList(rlp.EncodeBytes(compact), childRef)
}

func (n *extensionNode) hash() []byte {
	return crypto.Keccak256(n.encode())
}

func nibblesToCompact(nibbles []byte, isLeaf bool) []byte {
	var prefix byte
	if isLeaf {
		prefix = 2
	}
	odd := len(nibbles) % 2
	if odd == 1 {
		prefix |= 1
	}
	var compact []byte
	if odd == 1 {
		compact = append(compact, (prefix<<4)|nibbles[0])
		for i := 1; i < len(nibbles); i += 2 {
			compact = append(compact, (nibbles[i]<<4)|nibbles[i+1])
		}
	} else {
		compact = append(compact, prefix<<4)
		for i := 0; i < len(nibbles); i += 2 {
			compact = append(compact, (nibbles[i]<<4)|nibbles[i+1])
		}
	}
	return compact
}

func keyToNibbles(key []byte) []byte {
	nibbles := make([]byte, len(key)*2)
	for i, b := range key {
		nibbles[i*2] = b >> 4
		nibbles[i*2+1] = b & 0x0f
	}
	return nibbles
}

// BuildTrie builds an MPT from key-value pairs.
func BuildTrie(keys [][]byte, values [][]byte) trieNode {
	if len(keys) == 0 {
		return nil
	}
	nibbleKeys := make([][]byte, len(keys))
	for i, k := range keys {
		nibbleKeys[i] = keyToNibbles(k)
	}
	return buildNode(nibbleKeys, values, 0)
}

func buildNode(keys [][]byte, values [][]byte, depth int) trieNode {
	if len(keys) == 0 {
		return nil
	}
	if len(keys) == 1 {
		return &leafNode{keyNibbles: keys[0][depth:], value: values[0]}
	}
	commonLen := commonPrefixLen(keys, depth)
	if commonLen > 0 {
		return &extensionNode{
			keyNibbles: keys[0][depth : depth+commonLen],
			child:      buildNode(keys, values, depth+commonLen),
		}
	}
	branch := &branchNode{}
	for nibble := byte(0); nibble < 16; nibble++ {
		var subKeys [][]byte
		var subVals [][]byte
		for i, k := range keys {
			if depth < len(k) && k[depth] == nibble {
				subKeys = append(subKeys, k)
				subVals = append(subVals, values[i])
			}
		}
		if len(subKeys) > 0 {
			branch.children[nibble] = buildNode(subKeys, subVals, depth+1)
		}
	}
	for i, k := range keys {
		if len(k) == depth {
			branch.value = values[i]
		}
	}
	return branch
}

func commonPrefixLen(keys [][]byte, depth int) int {
	if len(keys) <= 1 {
		return 0
	}
	first := keys[0]
	maxLen := len(first) - depth
	for _, k := range keys[1:] {
		kLen := len(k) - depth
		if kLen < maxLen {
			maxLen = kLen
		}
	}
	common := 0
	for i := 0; i < maxLen; i++ {
		match := true
		for _, k := range keys[1:] {
			if k[depth+i] != first[depth+i] {
				match = false
				break
			}
		}
		if !match {
			break
		}
		common++
	}
	return common
}

// GenerateProof generates an MPT inclusion proof for the given key.
func GenerateProof(root trieNode, key []byte) [][]byte {
	nibbles := keyToNibbles(key)
	var proof [][]byte
	collectProof(root, nibbles, 0, &proof)
	return proof
}

func collectProof(node trieNode, nibbles []byte, depth int, proof *[][]byte) {
	if node == nil {
		return
	}
	*proof = append(*proof, node.encode())
	switch n := node.(type) {
	case *leafNode:
	case *branchNode:
		if depth < len(nibbles) {
			child := n.children[nibbles[depth]]
			if child != nil {
				collectProof(child, nibbles, depth+1, proof)
			}
		}
	case *extensionNode:
		collectProof(n.child, nibbles, depth+len(n.keyNibbles), proof)
	}
}

// TrieRoot returns the root hash of a built trie.
func TrieRoot(root trieNode) []byte {
	if root == nil {
		return crypto.Keccak256(rlp.EncodeBytes(nil))
	}
	return root.hash()
}
