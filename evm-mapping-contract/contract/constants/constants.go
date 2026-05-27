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
	GasReserveKey           = "gr"                   // gas reserve amount (gwei — scaled from wei at deposit input boundary per W4 Cluster A Step 3b)
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
	// hive account names are the canonical form of the caller string
	// at HandleMap entry (source-verified at contract/main.go:73 +
	// mapping/handlers.go:18 — env.Caller.String() is a Hive username
	// for L2 user-submitted calls).
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
// W4 Cluster A Step 3b gwei scaling: native ETH internal denomination moved
// from wei (18 decimals) to gwei (9 decimals). MinETHWithdrawal is now in
// gwei. 0.01 ETH = 10_000_000 gwei. See W4-cluster-A-deposit-pipeline.md
// "Step 3b" — sub-gwei dust (<1 gwei ≈ $0.000000003) is truncated at the
// deposit input boundary in mapping/proof.go::VerifyETHDeposit.
const MinETHWithdrawal = int64(10_000_000) // 0.01 ETH in GWEI (post-Step-3b)
const MinUSDCWithdrawal = int64(10_000_000)             // 10 USDC in micro-units

// Gas reserve
const GasReserveDepositTaxBps = int64(100) // 1% of ETH deposits go to gas reserve
// W4 Cluster A Step 3b gwei scaling: MinGasReserve moves to gwei.
// 0.05 ETH = 50_000_000 gwei. The full reserve accumulator (GasReserveKey)
// is now denominated in gwei. Operators calling `setGasReserve` MUST pass
// gwei values, not wei — see W0 P5 deploy runbook update.
const MinGasReserve = int64(50_000_000) // 0.05 ETH in GWEI minimum reserve

// W4 Cluster E CRIT #26 + D-E-3 (LOCKED): withdrawal auto-expiry window.
// EXPIRY_WINDOW = 5000 Hive blocks ≈ 4 hours (Hive 3s blocks). Any L2 caller
// can submit `expireWithdrawal` once currentBlock >= pending.BlockHeight +
// WithdrawalExpiryWindow with an L1-proof-of-drop per D-E-4. The original
// withdrawer can call `cancelMyWithdrawal` before the window with an L1
// inclusion check. Named constant per W4 N-E-1 fix (no magic number 5000).
const WithdrawalExpiryWindow uint64 = 5000

// W4 Cluster E §D-E-8 + Cluster B §BG: chain-gate state key set by
// initContract when IsTestnet=true. clearTestnetState reads this key and
// aborts if absent or != "true". Exported to keep clearTestnetState's
// chain-gate check in lockstep with Cluster B/C initContract writers.
const IsTestnetKey = "is_testnet"
