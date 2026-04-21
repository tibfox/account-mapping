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
