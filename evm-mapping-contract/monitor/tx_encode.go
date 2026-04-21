package monitor

import (
	"evm-mapping-contract/contract/rlp"
	"math/big"
	"strings"
)

// RPCTx represents a transaction from eth_getBlockByNumber with hydrated TXs.
type RPCTx struct {
	ChainId              string `json:"chainId"`
	Nonce                string `json:"nonce"`
	GasPrice             string `json:"gasPrice"`
	MaxPriorityFeePerGas string `json:"maxPriorityFeePerGas"`
	MaxFeePerGas         string `json:"maxFeePerGas"`
	Gas                  string `json:"gas"`
	To                   string `json:"to"`
	Value                string `json:"value"`
	Input                string `json:"input"`
	V                    string `json:"v"`
	R                    string `json:"r"`
	S                    string `json:"s"`
	Type                 string `json:"type"`
	Hash                 string `json:"hash"`
	AccessList           []struct {
		Address     string   `json:"address"`
		StorageKeys []string `json:"storageKeys"`
	} `json:"accessList"`
	MaxFeePerBlobGas    string   `json:"maxFeePerBlobGas"`
	BlobVersionedHashes []string `json:"blobVersionedHashes"`
	AuthorizationList   []struct {
		ChainId string `json:"chainId"`
		Address string `json:"address"`
		Nonce   string `json:"nonce"`
		YParity string `json:"yParity"`
		R       string `json:"r"`
		S       string `json:"s"`
	} `json:"authorizationList"`
}

// EncodeTx RLP-encodes a transaction from its JSON fields.
// Handles all TX types: legacy (0), access list (1), EIP-1559 (2), blob (3), set-code (4).
func EncodeTx(tx *RPCTx) []byte {
	txType := HexToUint(tx.Type)
	switch txType {
	case 2:
		return encodeEIP1559Tx(tx)
	case 3:
		return encodeBlobTx(tx)
	case 4:
		return encodeSetCodeTx(tx)
	case 1:
		return encodeAccessListTx(tx)
	default:
		return encodeLegacyTx(tx)
	}
}

func encodeEIP1559Tx(tx *RPCTx) []byte {
	body := rlp.EncodeList(
		rlp.EncodeUint64(HexToUint(tx.ChainId)),
		rlp.EncodeUint64(HexToUint(tx.Nonce)),
		encodeBigHex(tx.MaxPriorityFeePerGas),
		encodeBigHex(tx.MaxFeePerGas),
		rlp.EncodeUint64(HexToUint(tx.Gas)),
		rlp.EncodeBytes(HexToBytes(tx.To)),
		encodeBigHex(tx.Value),
		rlp.EncodeBytes(HexToBytes(tx.Input)),
		encodeAccessList(tx.AccessList),
		encodeBigHex(tx.V),
		encodeBigHex(tx.R),
		encodeBigHex(tx.S),
	)
	return append([]byte{0x02}, body...)
}

func encodeAccessListTx(tx *RPCTx) []byte {
	body := rlp.EncodeList(
		rlp.EncodeUint64(HexToUint(tx.ChainId)),
		rlp.EncodeUint64(HexToUint(tx.Nonce)),
		encodeBigHex(tx.GasPrice),
		rlp.EncodeUint64(HexToUint(tx.Gas)),
		rlp.EncodeBytes(HexToBytes(tx.To)),
		encodeBigHex(tx.Value),
		rlp.EncodeBytes(HexToBytes(tx.Input)),
		encodeAccessList(tx.AccessList),
		encodeBigHex(tx.V),
		encodeBigHex(tx.R),
		encodeBigHex(tx.S),
	)
	return append([]byte{0x01}, body...)
}

func encodeLegacyTx(tx *RPCTx) []byte {
	return rlp.EncodeList(
		rlp.EncodeUint64(HexToUint(tx.Nonce)),
		encodeBigHex(tx.GasPrice),
		rlp.EncodeUint64(HexToUint(tx.Gas)),
		rlp.EncodeBytes(HexToBytes(tx.To)),
		encodeBigHex(tx.Value),
		rlp.EncodeBytes(HexToBytes(tx.Input)),
		encodeBigHex(tx.V),
		encodeBigHex(tx.R),
		encodeBigHex(tx.S),
	)
}

func encodeBlobTx(tx *RPCTx) []byte {
	blobHashes := make([][]byte, len(tx.BlobVersionedHashes))
	for i, h := range tx.BlobVersionedHashes {
		blobHashes[i] = rlp.EncodeBytes(HexToBytes(h))
	}
	body := rlp.EncodeList(
		rlp.EncodeUint64(HexToUint(tx.ChainId)),
		rlp.EncodeUint64(HexToUint(tx.Nonce)),
		encodeBigHex(tx.MaxPriorityFeePerGas),
		encodeBigHex(tx.MaxFeePerGas),
		rlp.EncodeUint64(HexToUint(tx.Gas)),
		rlp.EncodeBytes(HexToBytes(tx.To)),
		encodeBigHex(tx.Value),
		rlp.EncodeBytes(HexToBytes(tx.Input)),
		encodeAccessList(tx.AccessList),
		encodeBigHex(tx.MaxFeePerBlobGas),
		rlp.EncodeList(blobHashes...),
		encodeBigHex(tx.V),
		encodeBigHex(tx.R),
		encodeBigHex(tx.S),
	)
	return append([]byte{0x03}, body...)
}

func encodeSetCodeTx(tx *RPCTx) []byte {
	authItems := make([][]byte, len(tx.AuthorizationList))
	for i, a := range tx.AuthorizationList {
		authItems[i] = rlp.EncodeList(
			rlp.EncodeUint64(HexToUint(a.ChainId)),
			rlp.EncodeBytes(HexToBytes(a.Address)),
			rlp.EncodeUint64(HexToUint(a.Nonce)),
			encodeBigHex(a.YParity),
			encodeBigHex(a.R),
			encodeBigHex(a.S),
		)
	}
	body := rlp.EncodeList(
		rlp.EncodeUint64(HexToUint(tx.ChainId)),
		rlp.EncodeUint64(HexToUint(tx.Nonce)),
		encodeBigHex(tx.MaxPriorityFeePerGas),
		encodeBigHex(tx.MaxFeePerGas),
		rlp.EncodeUint64(HexToUint(tx.Gas)),
		rlp.EncodeBytes(HexToBytes(tx.To)),
		encodeBigHex(tx.Value),
		rlp.EncodeBytes(HexToBytes(tx.Input)),
		encodeAccessList(tx.AccessList),
		rlp.EncodeList(authItems...),
		encodeBigHex(tx.V),
		encodeBigHex(tx.R),
		encodeBigHex(tx.S),
	)
	return append([]byte{0x04}, body...)
}

func encodeAccessList(al []struct {
	Address     string   `json:"address"`
	StorageKeys []string `json:"storageKeys"`
}) []byte {
	if len(al) == 0 {
		return rlp.EncodeList()
	}
	items := make([][]byte, len(al))
	for i, entry := range al {
		keys := make([][]byte, len(entry.StorageKeys))
		for j, k := range entry.StorageKeys {
			keys[j] = rlp.EncodeBytes(HexToBytes(k))
		}
		items[i] = rlp.EncodeList(
			rlp.EncodeBytes(HexToBytes(entry.Address)),
			rlp.EncodeList(keys...),
		)
	}
	return rlp.EncodeList(items...)
}

func encodeBigHex(s string) []byte {
	s = strings.TrimPrefix(s, "0x")
	if s == "" || s == "0" {
		return rlp.EncodeBytes(nil)
	}
	b, ok := new(big.Int).SetString(s, 16)
	if !ok || b == nil {
		return rlp.EncodeBytes(nil)
	}
	return rlp.EncodeBigInt(b)
}
