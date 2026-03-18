package mapping

// MapParams is the input to the map entrypoint.
// The oracle submits verified ETH deposit data.
//
//tinyjson:json
type MapParams struct {
	Deposits []EthDeposit `json:"deposits"`
}

// EthDeposit represents a single verified ETH deposit submitted by the oracle.
//
//tinyjson:json
type EthDeposit struct {
	TxHash string `json:"tx_hash"` // ETH transaction hash (for duplicate detection)
	Amount string `json:"amount"`  // deposit amount in wei
	Sender string `json:"sender"`  // ETH address that sent the deposit
	// Instruction is a URL-encoded string defining what to do with the deposit.
	// Examples: "deposit_to=hive:username" or "swap_to=hive:bob&swap_asset_out=HIVE"
	Instruction string `json:"instruction"`
}

// MappingType identifies whether a deposit is a direct credit or a DEX swap.
type MappingType string

const (
	MapDeposit MappingType = "deposit"
	MapSwap    MappingType = "swap"
)

// DexInstruction is the swap instruction sent to the DEX Router.
//
//tinyjson:json
type DexInstruction struct {
	Type      string `json:"type"`
	Version   string `json:"version"`
	AssetIn   string `json:"asset_in"`
	AssetOut  string `json:"asset_out"`
	Recipient string `json:"recipient"`
	AmountIn  string `json:"amount_in"`
}

// SwapResult holds the result returned by the DEX Router.
//
//tinyjson:json
type SwapResult struct {
	AmountOut string `json:"amount_out"`
}

// TransferParams is the input to unmap, transfer, and transferFrom entrypoints.
//
//tinyjson:json
type TransferParams struct {
	To     string `json:"to"`
	Amount string `json:"amount"`
	From   string `json:"from,omitempty"`
}

// AllowanceParams is the input for approve, increaseAllowance, decreaseAllowance.
//
//tinyjson:json
type AllowanceParams struct {
	Spender string `json:"spender"`
	Amount  string `json:"amount"`
}

// PublicKeys holds the primary and backup public keys for the contract.
//
//tinyjson:json
type PublicKeys struct {
	PrimaryPubKey string `json:"primary_pub_key"`
	BackupPubKey  string `json:"backup_pub_key"`
}

// RouterContract holds the router contract ID.
//
//tinyjson:json
type RouterContract struct {
	ContractId string `json:"contract_id"`
}

// SystemSupply tracks the supply state for the ETH mapping contract.
type SystemSupply struct {
	ActiveSupply uint64 `json:"active_supply"`
	UserSupply   uint64 `json:"user_supply"`
	FeeSupply    uint64 `json:"fee_supply"`
}
