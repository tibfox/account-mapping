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
	GasReserveKey           = "gr"                   // gas reserve amount (wei — full L1 native precision; big.Int-encoded decimal string)
	VaultAddressKey         = "vault"                // vault ETH address
	ChainIdKey              = "chainid"              // EVM chain ID
	VerifierContractIdKey   = "zkverifier"           // ZK header verifier contract ID

	// W4 Cluster C CRIT #9 (D-C-4 / v20 §BI): propose/execute timelock state.
	// KeyProposalCounter holds the monotonic uint64 proposal id source.
	// ProposalPrefix builds per-proposal storage keys ("pr-{id}").
	// The Go constant name AND the literal on-chain state key string for
	// the counter are both "proposal_next_id" per v20 §BI (resolves
	// S-C-v19-1 ambiguity — DO NOT shorten to "pc").
	KeyProposalCounter = "proposal_next_id"
	ProposalPrefix     = "pr" + DirPathDelimiter // pr-{proposalId} → JSON PendingProposal

	// W4 Cluster C CRIT #8 native ETH relayer whitelist (S-C-v17-2):
	// per-relayer entry stored under "rl-{hiveAccountName}" → "1".
	RelayerRegistryPrefix = "rl" + DirPathDelimiter // rl-{hive_account} → "1"

	// W4 Cluster C (v20 §BD): oracle account allowed to call addBlocks
	// without going through the propose/execute timelock. addBlocks must
	// remain a high-frequency operational path for the oracle relay; the
	// account identity itself is what is timelocked via setOracleAccount.
	OracleAccountKey = "oracle_account"

	// W4 Cluster C: initContract idempotency marker. initContract sets
	// this to "1" on first successful invocation to make subsequent
	// initContract calls fail (re-entry guard matching Cluster B §BF
	// pattern in zk-header-verifier).
	InitMarkerKey = "init"
)

const MaxBlockRetention = 101
const MaxMPTProofNodes = 20
const MaxMPTNodeSize = 4096

// Gas constants
const ETHTransferGas = uint64(21_000)
const ERC20TransferGas = uint64(65_000)

// Minimum withdrawal amounts (in token-native units).
// big.Int/wei migration: native ETH accounting is now full wei (18 decimals),
// no gwei scaling. These thresholds are bounded config values (well within
// int64) compared against big.Int amounts via big.NewInt at the call site;
// the unbounded accounting values (balances/supply/amounts) are *big.Int.
// 0.01 ETH = 10_000_000_000_000_000 wei.
const MinETHWithdrawal = int64(10_000_000_000_000_000) // 0.01 ETH in WEI
const MinUSDCWithdrawal = int64(10_000_000)            // 10 USDC in micro-units

// Gas reserve
const GasReserveDepositTaxBps = int64(100) // 1% of ETH deposits go to gas reserve
// big.Int/wei migration: the reserve accumulator (GasReserveKey) is denominated
// in WEI. Operators calling `setGasReserve` MUST pass wei values.
// 0.05 ETH = 50_000_000_000_000_000 wei.
const MinGasReserve = int64(50_000_000_000_000_000) // 0.05 ETH in WEI minimum reserve

// W4 Cluster E CRIT #26 + D-E-3 (LOCKED): withdrawal auto-expiry window.
// EXPIRY_WINDOW = 5000 Hive blocks ≈ 4 hours (Hive 3s blocks). Any L2 caller
// can submit `expireWithdrawal` once currentBlock >= pending.BlockHeight +
// WithdrawalExpiryWindow with an L1-proof-of-drop per D-E-4.
const WithdrawalExpiryWindow uint64 = 5000

// W4 Cluster E §D-E-8 + Cluster B §BG: chain-gate state key set by
// initContract when IsTestnet=true. clearTestnetState reads this key and
// aborts if absent or != "true".
const IsTestnetKey = "is_testnet"
