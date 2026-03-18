package constants

const DirPathDelimiter = "-"

const TssKeyName = "main"
const RouterContractIdKey = "routerid"

const BalancePrefix = "a" + DirPathDelimiter
const AllowancePrefix = "q" + DirPathDelimiter
const ObservedPrefix = "o" + DirPathDelimiter // observed deposit tx hashes

const OracleAddress = "did:vsc:oracle:eth"
const PrimaryPublicKeyStateKey = "pubkey"
const BackupPublicKeyStateKey = "backupkey"

const BlockPrefix = "block/"

// Instruction URL search param keys
const (
	DepositToKey   = "deposit_to"
	SwapAssetOut   = "swap_asset_out"
	SwapToKey      = "swap_to"
)

// Logs
const (
	LogDelimiter    = "|"
	LogKeyDelimiter = "="
)

const (
	Testnet string = "testnet"
	Mainnet string = "mainnet"
)

func IsTestnet(networkName string) bool {
	return networkName == Testnet
}
