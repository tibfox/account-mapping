package constants

const DirPathDelimiter = "-"

// State key prefixes — mirrors BTC contract pattern
const (
	BalancePrefix           = "a" + DirPathDelimiter // a-{address}-{asset} → balance
	AllowancePrefix         = "q" + DirPathDelimiter // q-{owner}-{spender}-{asset} → allowance
	ObservedBlockPrefix     = "o" + DirPathDelimiter // o-{height} → observed deposits
	BlockPrefix             = "b" + DirPathDelimiter // b-{height} → block header data
	TxSpendsPrefix          = "d" + DirPathDelimiter // d-{nonce} → pending withdrawal
	SupplyKey               = "s"                    // supply tracking
	LastHeightKey           = "h"                    // last known block height
	NonceConfirmedKey       = "n"                    // confirmed nonce
	NoncePendingKey         = "np"                   // next pending nonce
	TokenRegistryPrefix     = "t" + DirPathDelimiter // t-{address} → {symbol, decimals}
	PrimaryPublicKeyKey     = "pubkey"               // TSS primary public key
	RouterContractIdKey     = "routerid"             // DEX router contract ID
	PausedKey               = "paused"               // "1" when paused
	GasReserveKey           = "gr"                   // gas reserve amount (wei)
	VaultAddressKey         = "vault"                // vault ETH address
	ChainIdKey              = "chainid"              // EVM chain ID
)

const MaxBlockRetention = 101
const MaxMPTProofNodes = 20
const MaxMPTNodeSize = 4096

// Gas constants
const ETHTransferGas = uint64(21_000)
const ERC20TransferGas = uint64(65_000)

// Minimum withdrawal amounts (in token-native units)
const MinETHWithdrawal = int64(10_000_000_000_000_000) // 0.01 ETH in wei
const MinUSDCWithdrawal = int64(10_000_000)             // 10 USDC in micro-units

// Gas reserve
const GasReserveDepositTaxBps = int64(100) // 1% of ETH deposits go to gas reserve
const MinGasReserve = int64(50_000_000_000_000_000) // 0.05 ETH minimum reserve
