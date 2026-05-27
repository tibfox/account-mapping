package mapping

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"evm-mapping-contract/contract/abi"
	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/mpt"
	"evm-mapping-contract/contract/rlp"
	"evm-mapping-contract/sdk"
	"math"
	"math/big"
	"strconv"
)

// IsWhitelistedRelayer — W4 Cluster C CRIT #8 native-ETH frontrun mitigation
// (PARTIAL-CLOSES-AND-DEFERRALS.md item #1, v1 scope): native ETH path
// requires the caller to be a registered relayer. Registry entries are
// written by the propose/execute-wrapped `registerRelayer` admin handler.
//
// Source-verified at contract/main.go:73 + mapping/handlers.go:18:
// env.Caller.String() at HandleMap entry is the L2 caller string — for
// Hive user-submitted transactions this is the Hive account name. The
// registerRelayer handler stores under "rl-{accountName}" with identical
// normalization (no case-folding, no @-stripping) so the lookup matches.
//
// Cross-chain note: ERC-20 path is closed by the L1 calldata commitment
// in VerifyERC20Deposit's depositor-from-Transfer-log binding (the
// Transfer event's `from` field is the L1 sender and is part of the
// proven receipt). v2 work extends native ETH to a cryptographic L1
// binding (e.g. CREATE2 salt or calldata commitment); v1 closes the
// frontrun window via this whitelist.
func IsWhitelistedRelayer(account string) bool {
	if account == "" {
		return false
	}
	data := sdk.StateGetObject(constants.RelayerRegistryPrefix + account)
	return data != nil && *data == "1"
}

// SetRelayer / UnsetRelayer write / delete the per-relayer state entry.
// Called from the propose/execute dispatchAdmin switch in main.go after
// the operational-class timelock elapses.
func SetRelayer(account string) {
	sdk.StateSetObject(constants.RelayerRegistryPrefix+account, "1")
}

func UnsetRelayer(account string) {
	sdk.StateDeleteObject(constants.RelayerRegistryPrefix + account)
}

// AssertNotPaused — exported so main.go dispatchAdmin can gate every
// migrated handler with this BEFORE business logic, per W1 §D-C-9. The
// caller is responsible for already having passed the multisig-check.
func AssertNotPaused() error {
	if isPaused() {
		return errors.New("contract is paused")
	}
	return nil
}

// HandleMap — W4 Cluster B CRIT #6 Sites 1+2+3+10 + W4 Cluster C CRIT #8:
//   - chainId parameter threaded in from wasmexport so VerifyETHDeposit /
//     VerifyERC20Deposit can cross-check the parsed tx's chainId field
//     against the contract's configured chainId (rejects wrong-chain replay).
//   - routeDeposit now also takes chainId so AddressToDID produces the right
//     did:pkh prefix per network (was hardcoded `:1:` pre-fix).
//   - getTokenInfo is now called with (chainId, tokenAddr) so the token
//     registry is keyed by `(chainId, contractAddr)` tuple (Site 10).
//   - W4 Cluster C CRIT #8: native ETH path now requires the caller to be
//     a whitelisted relayer (PARTIAL-CLOSES-AND-DEFERRALS item #1 v1
//     mitigation). ERC-20 path stays permissionless because the
//     VerifyERC20Deposit Transfer-event proof binds depositor to L1
//     sender directly. The relayer check fires BEFORE any state mutation
//     (MarkObserved relocation per W4 Cluster A is preserved — the
//     observed slot is still written only AFTER full validation).
func HandleMap(params *MapParams, vaultAddress [20]byte, chainId uint64) error {
	if isPaused() {
		return errors.New("contract is paused")
	}
	if vaultAddress == ([20]byte{}) {
		return errors.New("vault address not configured")
	}

	req := &params.TxData

	switch req.DepositType {
	case "eth":
		// W4 Cluster C CRIT #8 (v1 relayer whitelist): native ETH has no
		// L1 calldata to commit `deposit_to` against, so the only v1
		// defense against the deposit-frontrun-and-steal vector is gating
		// `map` to approved relayer identities. The check fires here
		// (NOT in mapDeposit wasmexport) so the same gate applies to any
		// future call path that re-enters HandleMap.
		caller := sdk.GetEnv().Caller.String()
		if !IsWhitelistedRelayer(caller) {
			return errors.New("native ETH deposits require whitelisted relayer in v1")
		}
		// CRIT #8: VerifyETHDeposit no longer marks observed; the caller is
		// responsible for that AFTER routeDeposit + IncBalance + TrackDeposit
		// all succeed. The returned txHash is the L1-canonical hash used as
		// the dedup key.
		// W4 Cluster B CRIT #6 Site 1: chainId passed in so Verify*Deposit
		// can reject wrong-chain tx replay BEFORE state mutation.
		// W4 Cluster A Step 3b: amountBytes is GWEI (converted at the
		// proof.go INPUT BOUNDARY). int64 max in gwei = 9.22e18 gwei = 9.22
		// BILLION ETH, so the "exceeds safe int64 range" branch below is
		// physically unreachable for realistic deposits. The guard stays as
		// defense-in-depth (matches W2 SafeAdd64 posture — overflow is
		// impossible after gwei scaling, but the guard catches future
		// arithmetic bugs). Sub-gwei dust is truncated at the boundary
		// (acceptable per Step 3b: ≤$3e-9 per deposit at $3K ETH).
		sender, amountBytes, txHash, err := VerifyETHDeposit(req, vaultAddress, chainId)
		if err != nil {
			return err
		}

		amount := new(big.Int).SetBytes(amountBytes)
		if amount.Sign() <= 0 {
			return errors.New("deposit amount must be positive")
		}
		if !amount.IsInt64() || amount.Int64() <= 0 {
			return errors.New("deposit amount exceeds safe int64 range")
		}
		amountInt64 := amount.Int64()

		dest := routeDeposit(sender, params.Instructions, "eth", amountInt64, chainId)

		// Gas reserve tax: bps of ETH deposits (now denominated in gwei per
		// W4 Cluster A Step 3b — addGasReserve, deductGasReserve, getGasReserve
		// and the underlying GasReserveKey state slot all carry gwei units).
		// Compute as (amount/10000)*bps + (amount%10000)*bps/10000 so we keep
		// full precision without ever producing an int64 overflow on amount*bps.
		gasTax := (amountInt64/10000)*constants.GasReserveDepositTaxBps +
			(amountInt64%10000)*constants.GasReserveDepositTaxBps/10000
		if gasTax > 0 {
			addGasReserve(gasTax)
			amountInt64 -= gasTax
		}

		if dest != "" {
			if err := IncBalance(dest, "eth", amountInt64); err != nil {
				return errors.New("balance overflow")
			}
		}
		// CRIT #3: TrackDeposit now returns on supply-accumulator overflow.
		// W2 SafeAdd64 routing inside TrackDeposit is preserved.
		if err := TrackDeposit("eth", amountInt64, gasTax); err != nil {
			return err
		}
		// CRIT #8: deposit fully routed and credited; lock the observed slot
		// so a replay cannot re-credit. txIndex is the dedup secondary index
		// (per snapshot convention; see observed.go).
		MarkObserved(req.BlockHeight, txHash, uint16(req.TxIndex))
		return nil

	case "erc20":
		tokenAddr, err := crypto.HexToAddress(req.TokenAddress)
		if err != nil {
			return errors.New("invalid token address")
		}

		// W4 Cluster B CRIT #6 Site 10: token registry is keyed by
		// (chainId, contractAddr). A token registered on chain X must NOT
		// be looked up by a deposit allegedly mined on chain Y.
		tokenInfo := getTokenInfo(chainId, tokenAddr)
		if tokenInfo == nil {
			return ErrInvalidToken
		}

		// CRIT #8: VerifyERC20Deposit no longer marks observed.
		// W4 Cluster B CRIT #6 Site 2: chainId threaded for wrong-chain
		// rejection in the ERC-20 path.
		sender, amountBytes, txHash, err := VerifyERC20Deposit(req, vaultAddress, tokenAddr, chainId)
		if err != nil {
			return err
		}

		amount := new(big.Int).SetBytes(amountBytes)
		if amount.Sign() <= 0 || !amount.IsInt64() || amount.Int64() <= 0 {
			return errors.New("deposit amount invalid or exceeds safe range")
		}
		amountInt64 := amount.Int64()

		dest := routeDeposit(sender, params.Instructions, tokenInfo.Symbol, amountInt64, chainId)
		if dest != "" {
			if err := IncBalance(dest, tokenInfo.Symbol, amountInt64); err != nil {
				return errors.New("balance overflow")
			}
		}
		// CRIT #3: TrackDeposit now returns on supply-accumulator overflow.
		// W2 SafeAdd64 routing preserved.
		if err := TrackDeposit(tokenInfo.Symbol, amountInt64, 0); err != nil {
			return err
		}
		// CRIT #8 + CRIT #14: lock observed slot only after routing + credit
		// succeed. req.LogIndex is per-receipt (0..N-1 within this tx's own
		// log list); writers (monitor + bot) emit per-receipt logIndex.
		MarkObserved(req.BlockHeight, txHash, uint16(req.LogIndex))
		return nil

	default:
		return errors.New("deposit_type must be 'eth' or 'erc20'")
	}
}

func HandleUnmapETH(params *TransferParams, vaultAddress [20]byte, chainId uint64) (string, error) {
	if isPaused() {
		return "", errors.New("contract is paused")
	}
	if HasPendingWithdrawal() {
		return "", errors.New("withdrawal pending: wait for confirmation")
	}

	env := sdk.GetEnv()
	caller := env.Caller.String()

	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil || amount <= 0 {
		return "", errors.New("invalid amount")
	}
	if amount < constants.MinETHWithdrawal {
		return "", errors.New("below minimum ETH withdrawal")
	}

	toAddr, err := crypto.HexToAddress(params.To)
	if err != nil {
		return "", errors.New("invalid 'to' address")
	}

	header := blocklist.GetHeader(blocklist.GetLastHeight())
	if header == nil {
		return "", errors.New("no block headers available")
	}

	// W4 Cluster A Step 3b: gas reserve is now denominated in gwei. The
	// MinGasReserve constant moved from 5e16 wei → 5e7 gwei (= 0.05 ETH).
	// HIGH #40 / W2 max_fee semantics stay in wei (gas units × wei/gas) —
	// only the amount + reserve fields move to gwei. The fee value we
	// compute below is initially in wei (gas math) and is divided by 1e9
	// to land in gwei before it is added to the gwei-denominated `amount`.
	gasReserve := getGasReserve()
	if gasReserve < constants.MinGasReserve {
		return "", errors.New("insufficient gas reserve")
	}

	gasTipCap := uint64(2_000_000_000)                  // 2 gwei (wei units of gas pricing)
	gasFeeCap := header.BaseFeePerGas*2 + gasTipCap
	// W4 Cluster A Step 3b FEE BOUNDARY (wei -> gwei): the raw fee is
	// ETHTransferGas * gasFeeCap = wei. params.MaxFee semantics (HIGH #40 /
	// W2 — non-negative + maxFee=0 means "no fees accepted") stay in WEI so
	// existing operator/UI tooling that quotes max_fee in wei keeps
	// working. After the cap check, divide by 1e9 to land in gwei so the
	// SafeAdd64(amount, fee) below operates on like denominations.
	// Integer division truncates sub-gwei fee dust (≤ 1 gwei per
	// withdrawal); acknowledged as one-directional bias in Step 3b.
	feeWei := int64(constants.ETHTransferGas * gasFeeCap)

	if params.MaxFee != "" {
		maxFee, err := strconv.ParseInt(params.MaxFee, 10, 64)
		if err != nil {
			return "", errors.New("invalid max_fee")
		}
		// HIGH #40: reject negative max_fee instead of silently disabling the cap.
		if maxFee < 0 {
			return "", errors.New("max_fee must be non-negative")
		}
		// HIGH #40: maxFee=0 must mean "no fees accepted" — drop the
		// `maxFee > 0` short-circuit that previously bypassed the gate.
		// max_fee semantics are WEI (per Step 3b decision: gas pricing
		// stays in wei because it lines up with L1 gas math).
		if feeWei > maxFee {
			return "", errors.New("fee exceeds max_fee")
		}
	}

	// W4 Cluster A Step 3b: convert wei fee to gwei before mixing with
	// gwei-denominated amount/balance. Truncation is acceptable dust.
	fee := feeWei / 1_000_000_000

	// CRIT #3 / W2 SafeAdd64: replace the unchecked `amount + fee` with a
	// safe-add. Pre-gwei-scaling these int64 values could wrap negative on
	// adversarial inputs; post-gwei-scaling the wrap is physically
	// unreachable but the guard stays as defense-in-depth.
	// Check balance BEFORE signing to prevent signed TX leak on insufficient funds
	totalDeduct, err := SafeAdd64(amount, fee)
	if err != nil {
		return "", errors.New("amount+fee overflow")
	}
	if params.DeductFee {
		totalDeduct = amount
	}
	if GetBalance(caller, "eth") < totalDeduct {
		return "", errors.New("insufficient balance")
	}

	nonce := GetPendingNonce()
	// W4 Cluster A Step 3b OUTPUT BOUNDARY (gwei -> wei): the L1 tx value
	// is wei (L1 native unit). amount is stored in gwei; multiply by 1e9
	// before building the unsigned tx. No overflow risk: amount * 1e9 fits
	// in big.Int unconditionally.
	amountBig := new(big.Int).Mul(big.NewInt(amount), WeiPerGwei)
	unsigned := BuildETHWithdrawalTx(chainId, nonce, gasTipCap, gasFeeCap, toAddr, amountBig)
	sighash := ComputeSighash(unsigned)

	if err := requireTssKey(); err != nil {
		return "", err
	}
	sdk.TssSignKey("primary", sighash)

	if !DecBalance(caller, "eth", totalDeduct) {
		return "", errors.New("insufficient balance")
	}
	TrackWithdrawal("eth", amount)

	// Store pending spend. CRIT #17 flag 3 / W4 Cluster F D-F-3: snapshot
	// the CURRENT vault address into VaultAtQueue at queue time. When
	// confirmSpend lands (potentially after a setVault rotation),
	// HandleConfirmSpend ecrecovers against ps.VaultAtQueue, NOT the
	// current vault — this closes HIGH #29 (setVault orphans pending).
	// VaultAtQueue is the canonical 0x-prefixed lowercase hex per v20 §BE
	// (NOT [20]byte, which JSON-marshals as base64).
	StorePendingSpend(PendingSpend{
		Nonce:         nonce,
		Amount:        amount,
		From:          caller,
		To:            params.To,
		Asset:         "eth",
		UnsignedTxHex: hex.EncodeToString(unsigned),
		BlockHeight:   blocklist.GetLastHeight(),
		VaultAtQueue:  "0x" + hex.EncodeToString(vaultAddress[:]),
	})
	SetPendingNonce(nonce + 1)

	return hex.EncodeToString(unsigned), nil
}

func HandleUnmapERC20(params *TransferParams, vaultAddress [20]byte, chainId uint64) (string, error) {
	if isPaused() {
		return "", errors.New("contract is paused")
	}
	if HasPendingWithdrawal() {
		return "", errors.New("withdrawal pending: wait for confirmation")
	}

	env := sdk.GetEnv()
	caller := env.Caller.String()

	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil || amount <= 0 {
		return "", errors.New("invalid amount")
	}
	if params.TokenAddress == "" {
		return "", errors.New("token_address required for ERC-20 withdrawal")
	}
	tokenAddr, err := crypto.HexToAddress(params.TokenAddress)
	if err != nil {
		return "", errors.New("invalid token_address")
	}
	// W4 Cluster B CRIT #6 Site 10: token registry keyed by (chainId, addr).
	tokenInfo := getTokenInfo(chainId, tokenAddr)
	if tokenInfo == nil {
		return "", ErrInvalidToken
	}
	if amount < tokenInfo.MinWithdrawal {
		return "", errors.New("below minimum withdrawal for this token")
	}

	recipientAddr, err := crypto.HexToAddress(params.To)
	if err != nil {
		return "", errors.New("invalid recipient address")
	}

	header := blocklist.GetHeader(blocklist.GetLastHeight())
	if header == nil {
		return "", errors.New("no block headers available")
	}

	gasReserve := getGasReserve()
	if gasReserve < constants.MinGasReserve {
		return "", errors.New("insufficient gas reserve for ERC-20 withdrawal")
	}

	gasTipCap := uint64(2_000_000_000)
	gasFeeCap := header.BaseFeePerGas*2 + gasTipCap
	// W4 Cluster A Step 3b site #14 (CRITICAL): gas reserve is now gwei.
	// L1 gas cost = ERC20TransferGas * gasFeeCap is in wei. Without the
	// /1e9 conversion below, EACH ERC-20 withdrawal would drain the gas
	// reserve 1e9x too fast — the reserve would hit zero after the first
	// USDC withdrawal at non-trivial gas prices, bricking ALL subsequent
	// withdrawals. Divide-by-1e9 truncates sub-gwei dust.
	gasCostWei := int64(constants.ERC20TransferGas * gasFeeCap)
	gasCost := gasCostWei / 1_000_000_000

	nonce := GetPendingNonce()
	// W4 Cluster A Step 3b: ERC-20 amounts are TOKEN-NATIVE (USDC=6 decimals),
	// NOT scaled. Only the native ETH path moves to gwei.
	amountBig := new(big.Int).SetInt64(amount)
	unsigned := BuildERC20WithdrawalTx(chainId, nonce, gasTipCap, gasFeeCap, tokenAddr, recipientAddr, amountBig)
	sighash := ComputeSighash(unsigned)

	if err := requireTssKey(); err != nil {
		return "", err
	}
	sdk.TssSignKey("primary", sighash)

	if !DecBalance(caller, tokenInfo.Symbol, amount) {
		return "", errors.New("insufficient token balance")
	}
	TrackWithdrawal(tokenInfo.Symbol, amount)

	deductGasReserve(gasCost)

	// CRIT #17 flag 3 / W4 Cluster F D-F-3: snapshot vault for ERC-20 path too.
	StorePendingSpend(PendingSpend{
		Nonce:         nonce,
		Amount:        amount,
		From:          caller,
		To:            params.To,
		Asset:         tokenInfo.Symbol,
		TokenAddress:  params.TokenAddress,
		UnsignedTxHex: hex.EncodeToString(unsigned),
		BlockHeight:   blocklist.GetLastHeight(),
		VaultAtQueue:  "0x" + hex.EncodeToString(vaultAddress[:]),
	})
	SetPendingNonce(nonce + 1)

	return hex.EncodeToString(unsigned), nil
}

// ConfirmSpendSchemaJSON — W4 Cluster E CRIT #5 (D-E-1): canonical wire
// schema returned by the `confirmSpendSchema` wasmexport so the bot can
// introspect the contract's expected payload shape at startup. If a bot
// build's hard-coded schema fingerprint diverges from this string, the
// bot logs a warning (see D-E-1 backward-compat note) but does NOT
// fatal-exit — the export's presence is optional, the schema is not.
//
// Field order MUST match types.go ConfirmSpendRequest. Indented for
// human-readability over the wire (JSON is whitespace-insensitive).
const ConfirmSpendSchemaJSON = `{` +
	`"struct":"ConfirmSpendRequest","version":1,` +
	`"fields":[` +
	`{"name":"block_height","type":"uint64"},` +
	`{"name":"tx_index","type":"uint64"},` +
	`{"name":"tx_hex","type":"string"},` +
	`{"name":"tx_proof_hex","type":"string"},` +
	`{"name":"receipt_hex","type":"string"},` +
	`{"name":"receipt_proof_hex","type":"string"},` +
	`{"name":"intent_nonce","type":"uint64"},` +
	`{"name":"intent_to","type":"string"},` +
	`{"name":"intent_amount","type":"int64"},` +
	`{"name":"intent_asset","type":"string"}` +
	`]}`

// CRIT #17 flag 3 / W4 Cluster F D-F-3 (S-F-v17-2): vaultAddress parameter
// REMOVED from HandleConfirmSpend. The handler reads ps.VaultAtQueue
// directly from the stored PendingSpend (snapshotted at queue time). The
// confirmSpend wasmexport in contract/main.go no longer passes vault().
//
// W4 Cluster E CRIT #5 + HIGH #13 (D-E-1 + D-E-2 LOCKED): the request now
// carries 4 intent fields (IntentNonce/To/Amount/Asset). Entry-point intent
// binding (lines below) verifies all 4 match the looked-up PendingSpend
// BEFORE any proof verification — this is the primary HIGH #13 gate. The
// downstream tx-proof checks are now defense-in-depth.
func HandleConfirmSpend(req *ConfirmSpendRequest, chainId uint64) error {
	if isPaused() {
		return errors.New("contract is paused")
	}

	confirmedNonce := GetConfirmedNonce()
	ps := GetPendingSpend(confirmedNonce)
	if ps == nil {
		return errors.New("no pending spend at confirmed nonce")
	}

	// W4 Cluster E HIGH #13 entry-point intent binding (D-E-2 SERIOUS-1).
	// These 4 checks fire BEFORE any tx proof verification — without them,
	// the intent fields are carried on the wire but never gate the action,
	// defeating HIGH #13. The downstream tx-proof checks remain as
	// defense-in-depth.
	if req.IntentNonce != confirmedNonce {
		return errors.New("intent fields do not match pending spend: nonce")
	}
	if req.IntentTo != ps.To {
		return errors.New("intent fields do not match pending spend: to")
	}
	if req.IntentAmount != ps.Amount {
		return errors.New("intent fields do not match pending spend: amount")
	}
	if req.IntentAsset != ps.Asset {
		return errors.New("intent fields do not match pending spend: asset")
	}

	if req.BlockHeight <= ps.BlockHeight {
		return errors.New("confirmation block must be after withdrawal block")
	}

	header := blocklist.GetHeader(req.BlockHeight)
	if header == nil {
		return ErrBlockNotFound
	}

	// --- Transaction proof: verify the tx matches the pending spend ---
	txBytes, err := hex.DecodeString(req.TxHex)
	if err != nil {
		return errors.New("invalid tx_hex")
	}
	txProofBytes, err := hex.DecodeString(req.TxProofHex)
	if err != nil {
		return errors.New("invalid tx_proof_hex")
	}

	txProof := splitProofNodes(txProofBytes)
	txKey := rlp.EncodeUint64(req.TxIndex)
	provenTx, err := mpt.VerifyProof(header.TransactionsRoot, txKey, txProof)
	if err != nil {
		return errors.New("tx proof verification failed")
	}
	if !bytesEqual(provenTx, txBytes) {
		return errors.New("tx does not match proof")
	}

	parsedTx, err := parseTransaction(txBytes)
	if err != nil {
		return errors.New("failed to parse proven tx: " + err.Error())
	}
	if parsedTx.Nonce != ps.Nonce {
		return errors.New("tx nonce does not match pending spend")
	}
	if parsedTx.ChainId != chainId {
		return errors.New("tx chain id does not match contract chain id")
	}

	// CRIT #11 site 6 (SYSTEM, REJECT): vault TSS-sig recovery. Post
	// CRIT #24, TSS-lib always produces low-S signatures, so high-S here
	// signals tampering or replay-with-malleated-sig. Use EcrecoverStrict
	// to reject without ever surfacing a recovered address.
	//
	// CRIT #17 flag 3 / W4 Cluster F D-F-3 (HIGH #29 closure): the
	// comparison target is ps.VaultAtQueue (snapshotted at unmap time),
	// NOT the current vault. setVault between unmap and confirmSpend
	// no longer orphans the pending withdrawal — the TSS signature
	// targeting the OLD vault still verifies against the OLD vault.
	//
	// Zero-VaultAtQueue check (S-F-v18-1 + v20 §BE): a pre-upgrade
	// PendingSpend that survived the testnet state wipe would have an
	// empty or zero-address VaultAtQueue. Fail explicitly rather than
	// silently fall back to a current-vault comparison that could
	// succeed against the wrong vault.
	if ps.VaultAtQueue == "" || ps.VaultAtQueue == "0x0000000000000000000000000000000000000000" {
		return errors.New("VaultAtQueue is zero — pre-upgrade PendingSpend entry; use clearNonce (with L1-proof-of-drop) or wait for W0 P0 state clearing")
	}
	snapshottedVault, err := crypto.HexToAddress(ps.VaultAtQueue)
	if err != nil {
		return errors.New("VaultAtQueue parse failed: " + err.Error())
	}
	sighash := computeTxSighash(txBytes, parsedTx)
	recoveredSender, err := crypto.EcrecoverStrict(sighash, 27+parsedTx.V, padTo32(parsedTx.R), padTo32(parsedTx.S))
	if err != nil {
		return errors.New("ecrecover failed: " + err.Error())
	}
	if recoveredSender != snapshottedVault {
		return errors.New("tx not signed by vault at queue time")
	}

	psTo, err := crypto.HexToAddress(ps.To)
	if err != nil {
		return errors.New("invalid pending spend destination")
	}
	if ps.Asset == "eth" {
		if parsedTx.To != psTo {
			return errors.New("tx destination does not match pending spend")
		}
		// W4 Cluster A Step 3b INPUT BOUNDARY (wei -> gwei): the L1 tx
		// value is wei; ps.Amount is gwei (stored at unmap time via
		// HandleUnmapETH/HandleUnmapFrom). Divide by 1e9 to compare on
		// the same denomination. big.Int.Div truncates toward zero —
		// MUST use identical semantics to VerifyETHDeposit's deposit-side
		// truncation (see proof.go::VerifyETHDeposit "INPUT BOUNDARY"
		// comment). A deposit/withdrawal pair with the same wei-level
		// sub-gwei remainder yields identical gwei integer parts, so
		// truncation invariant holds bit-for-bit.
		txAmountWei := new(big.Int).SetBytes(parsedTx.Value)
		txAmountGwei := new(big.Int).Div(txAmountWei, WeiPerGwei)
		if !txAmountGwei.IsInt64() || txAmountGwei.Int64() != ps.Amount {
			return errors.New("tx amount does not match pending spend")
		}
	} else {
		// ERC-20: tx.to is the token contract, value is 0, calldata is transfer(recipient, amount).
		tokenAddr, err := crypto.HexToAddress(ps.TokenAddress)
		if err != nil {
			return errors.New("invalid pending spend token address")
		}
		if parsedTx.To != tokenAddr {
			return errors.New("tx token contract does not match pending spend")
		}
		if new(big.Int).SetBytes(parsedTx.Value).Sign() != 0 {
			return errors.New("erc20 tx must have zero value")
		}
		if len(parsedTx.Data) != 68 {
			return errors.New("erc20 calldata must be 68 bytes")
		}
		if !bytesEqual(parsedTx.Data[0:4], abi.TransferSelector) {
			return errors.New("erc20 calldata selector mismatch")
		}
		// First 12 bytes of address slot must be zero (left-padded address).
		for _, b := range parsedTx.Data[4:16] {
			if b != 0 {
				return errors.New("erc20 recipient padding non-zero")
			}
		}
		if !bytesEqual(parsedTx.Data[16:36], psTo[:]) {
			return errors.New("erc20 recipient does not match pending spend")
		}
		callAmount := new(big.Int).SetBytes(parsedTx.Data[36:68])
		if !callAmount.IsInt64() || callAmount.Int64() != ps.Amount {
			return errors.New("erc20 amount does not match pending spend")
		}
	}

	// --- Receipt proof: determine success or failure ---
	receiptBytes, err := hex.DecodeString(req.ReceiptHex)
	if err != nil {
		return errors.New("invalid receipt_hex")
	}
	receiptProofBytes, err := hex.DecodeString(req.ReceiptProofHex)
	if err != nil {
		return errors.New("invalid receipt_proof_hex")
	}

	receiptProof := splitProofNodes(receiptProofBytes)
	receiptKey := rlp.EncodeUint64(req.TxIndex)
	provenReceipt, err := mpt.VerifyProof(header.ReceiptsRoot, receiptKey, receiptProof)
	if err != nil {
		return errors.New("receipt proof verification failed")
	}
	if !bytesEqual(provenReceipt, receiptBytes) {
		return errors.New("receipt does not match proof")
	}

	receiptToParse := receiptBytes
	if len(receiptToParse) > 0 && receiptToParse[0] <= 0x7f {
		receiptToParse = receiptToParse[1:]
	}
	items, err := rlp.DecodeList(receiptToParse)
	if err != nil || len(items) < 1 {
		return errors.New("invalid receipt RLP")
	}
	status := items[0].AsUint64()

	if status == 1 {
		DeletePendingSpend(confirmedNonce)
		SetConfirmedNonce(confirmedNonce + 1)
	} else {
		// Best-effort refund. If IncBalance overflows (user already at int64 max),
		// we still clear pending state — otherwise the contract is permanently
		// jammed for a near-impossible scenario. Only update supply when the
		// refund actually landed so balance and supply stay consistent.
		// CRIT #3: route the supply accumulators through SafeAdd64; if either
		// overflows, skip the supply update (balance already credited).
		if err := IncBalance(ps.From, ps.Asset, ps.Amount); err == nil {
			s := GetSupply(ps.Asset)
			newActive, errA := SafeAdd64(s.Active, ps.Amount)
			newUser, errU := SafeAdd64(s.User, ps.Amount)
			if errA == nil && errU == nil {
				s.Active = newActive
				s.User = newUser
				SetSupply(ps.Asset, s)
			}
		}
		DeletePendingSpend(confirmedNonce)
		SetConfirmedNonce(confirmedNonce + 1)
	}

	return nil
}

func HandleTransfer(params *TransferParams) error {
	if isPaused() {
		return errors.New("contract is paused")
	}
	env := sdk.GetEnv()
	caller := env.Caller.String()

	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil || amount <= 0 {
		return errors.New("invalid amount")
	}

	if !DecBalance(caller, params.Asset, amount) {
		return errors.New("insufficient balance")
	}
	if err := IncBalance(params.To, params.Asset, amount); err != nil {
		return errors.New("recipient balance overflow")
	}
	return nil
}

func HandleTransferFrom(params *TransferParams) error {
	if isPaused() {
		return errors.New("contract is paused")
	}
	env := sdk.GetEnv()
	caller := env.Caller.String()

	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil || amount <= 0 {
		return errors.New("invalid amount")
	}

	allowance := GetAllowance(params.From, caller, params.Asset)
	if allowance < amount {
		return errors.New("insufficient allowance")
	}

	if !DecBalance(params.From, params.Asset, amount) {
		return errors.New("insufficient balance")
	}
	SetAllowance(params.From, caller, params.Asset, allowance-amount)
	if err := IncBalance(params.To, params.Asset, amount); err != nil {
		return errors.New("recipient balance overflow")
	}
	return nil
}

func HandleApprove(params *AllowanceParams) error {
	if isPaused() {
		return errors.New("contract is paused")
	}
	env := sdk.GetEnv()
	caller := env.Caller.String()

	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil || amount < 0 {
		return errors.New("invalid amount")
	}

	SetAllowance(caller, params.Spender, params.Asset, amount)
	return nil
}

// Helpers

func routeDeposit(sender [20]byte, instructions []string, asset string, amount int64, chainId uint64) string {
	// W4 Cluster B CRIT #6 Site 3: chainId threaded through from
	// HandleMap (which gets it from main.go's chainId() helper reading
	// the immutable state slot). Old code passed literal 1 here, which
	// produced mainnet DIDs on testnet routing.
	did := crypto.AddressToDID(sender, chainId)
	dest := did
	var swapTo, assetOut, destChain string

	for _, instr := range instructions {
		if len(instr) > 11 && instr[:11] == "deposit_to=" {
			dest = instr[11:]
		}
		if len(instr) > 8 && instr[:8] == "swap_to=" {
			swapTo = instr[8:]
		}
		if len(instr) > 10 && instr[:10] == "asset_out=" {
			assetOut = instr[10:]
		}
		if len(instr) > 18 && instr[:18] == "destination_chain=" {
			destChain = instr[18:]
		}
	}

	if swapTo != "" && assetOut != "" {
		routerIdPtr := sdk.StateGetObject(constants.RouterContractIdKey)
		if routerIdPtr == nil || *routerIdPtr == "" {
			return dest
		}
		routerId := *routerIdPtr
		env := sdk.GetEnv()
		selfAddr := "contract:" + env.ContractId

		if err := IncBalance(selfAddr, asset, amount); err != nil {
			return dest
		}
		SetAllowance(selfAddr, "contract:"+routerId, asset, amount)

		instrJSON, _ := json.Marshal(DexInstruction{
			Type:             "swap",
			Version:          "1.0.0",
			AssetIn:          asset,
			AmountIn:         strconv.FormatInt(amount, 10),
			AssetOut:         assetOut,
			Recipient:        swapTo,
			DestinationChain: destChain,
		})

		result := sdk.ContractCall(routerId, "execute", string(instrJSON), nil)
		SetAllowance(selfAddr, "contract:"+routerId, asset, 0)

		if result == nil {
			// Router call failed. Reverse the self-balance credit and fall through
			// to credit the depositor directly with the original asset.
			DecBalance(selfAddr, asset, amount)
			return dest
		}
		return ""
	}

	return dest
}

func isPaused() bool {
	data := sdk.StateGetObject(constants.PausedKey)
	return data != nil && *data == "1"
}

// getTokenInfo / RegisterToken — W4 Cluster B CRIT #6 Site 10:
// state key changes from `t-<addr>` to `t-<chainId>-<addr>`. Pre-fix, a
// token registered on chainId=1 (mainnet) was indistinguishable from one
// registered on chainId=11155111 (sepolia), letting an attacker register
// a malicious sepolia contract under the mainnet USDC slot. Post-fix, the
// key is namespaced — registration and lookup are both keyed by tuple.
//
// Migration note: any pre-fix `t-<addr>` keys survive on testnet but are
// silently unreachable (lookup uses new key format); operator must
// re-register tokens via registerToken on the upgraded contract. Mainnet
// is fresh deploy.
func getTokenInfo(chainId uint64, addr [20]byte) *TokenInfo {
	key := constants.TokenRegistryPrefix + strconv.FormatUint(chainId, 10) + constants.DirPathDelimiter + hex.EncodeToString(addr[:])
	data := sdk.StateGetObject(key)
	if data == nil {
		return nil
	}
	// Format: symbol|decimals|minWithdrawal
	fields := splitPipe(*data)
	if len(fields) < 2 {
		return nil
	}
	dec, _ := strconv.ParseUint(fields[1], 10, 8)
	info := &TokenInfo{Symbol: fields[0], Decimals: uint8(dec)}
	if len(fields) >= 3 {
		info.MinWithdrawal, _ = strconv.ParseInt(fields[2], 10, 64)
	}
	if info.MinWithdrawal <= 0 {
		info.MinWithdrawal = constants.MinUSDCWithdrawal
	}
	return info
}

// RegisterToken — W4 Cluster B CRIT #6 Site 10: store key now includes chainId.
func RegisterToken(chainId uint64, addr [20]byte, symbol string, decimals uint8, minWithdrawal int64) {
	key := constants.TokenRegistryPrefix + strconv.FormatUint(chainId, 10) + constants.DirPathDelimiter + hex.EncodeToString(addr[:])
	sdk.StateSetObject(key, symbol+"|"+strconv.FormatUint(uint64(decimals), 10)+"|"+strconv.FormatInt(minWithdrawal, 10))
}

func requireTssKey() error {
	keyInfo := sdk.TssGetKey("primary")
	if keyInfo == "" || keyInfo == "fail" {
		return errors.New("TSS key not available")
	}
	return nil
}

func getGasReserve() int64 {
	data := sdk.StateGetObject(constants.GasReserveKey)
	if data == nil {
		return 0
	}
	v, _ := strconv.ParseInt(*data, 10, 64)
	return v
}

func addGasReserve(amount int64) {
	// CRIT #3: safe-add the gas reserve accumulator. On overflow, saturate
	// at MaxInt64 — the gas reserve is contract-internal and never debited
	// to user balances, so saturation is preferred to a revert that would
	// jam deposit ingestion.
	current := getGasReserve()
	newVal, err := SafeAdd64(current, amount)
	if err != nil {
		newVal = math.MaxInt64
	}
	sdk.StateSetObject(constants.GasReserveKey, strconv.FormatInt(newVal, 10))
}

func deductGasReserve(amount int64) {
	current := getGasReserve()
	newVal := current - amount
	if newVal < 0 {
		newVal = 0
	}
	sdk.StateSetObject(constants.GasReserveKey, strconv.FormatInt(newVal, 10))
}


// HandleUnmapFrom — W4 Cluster C CRIT #7 (M18-D16 gas-free drain) FIX:
// pre-fix the ETH path of unmapFrom never computed a gas fee, never called
// getGasReserve() for the floor check, and only debited `amount` from the
// owner balance — leaving the vault eating the L1 mining fee on every
// withdrawal at a ~10:1 ratio. Post-fix mirrors HandleUnmapETH:
//   - compute gasTipCap / gasFeeCap from the latest header (same as ETH path)
//   - compute fee = ETHTransferGas * gasFeeCap
//   - call getGasReserve() and reject if reserve < MinGasReserve
//   - debit (amount + fee) from the owner balance via SafeAdd64 (W2's
//     overflow helper — DO NOT re-inline the arithmetic; W2 owns the
//     SafeAdd64 routing at this file)
//
// ERC-20 path of unmapFrom already deducts gasCost from the gas reserve
// via deductGasReserve() below; this is preserved unchanged.
func HandleUnmapFrom(params *TransferParams, vaultAddress [20]byte, chainId uint64) error {
	if isPaused() {
		return errors.New("contract is paused")
	}
	if HasPendingWithdrawal() {
		return errors.New("withdrawal pending: wait for confirmation")
	}

	env := sdk.GetEnv()
	caller := env.Caller.String()

	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil || amount <= 0 {
		return errors.New("invalid amount")
	}
	if params.Asset == "eth" && amount < constants.MinETHWithdrawal {
		return errors.New("below minimum ETH withdrawal")
	}

	if err := requireTssKey(); err != nil {
		return err
	}

	// Validate ALL inputs BEFORE any state mutations
	toAddr, err := crypto.HexToAddress(params.To)
	if err != nil {
		return errors.New("invalid destination address")
	}

	header := blocklist.GetHeader(blocklist.GetLastHeight())
	if header == nil {
		return errors.New("no block headers available")
	}

	// W4 Cluster C CRIT #7: compute gas fee for BOTH paths up front so the
	// reserve floor check applies to ETH-path withdrawals (pre-fix the floor
	// check was only run on the ERC-20 path; the ETH path skipped it
	// entirely, drained the vault, and never deducted fees from the owner).
	gasTipCap := uint64(2_000_000_000) // 2 gwei
	gasFeeCap := header.BaseFeePerGas*2 + gasTipCap

	var tokenAddr [20]byte
	if params.Asset != "eth" {
		if params.TokenAddress == "" {
			return errors.New("token_address required")
		}
		tokenAddr, err = crypto.HexToAddress(params.TokenAddress)
		if err != nil {
			return errors.New("invalid token_address")
		}
		// W4 Cluster B CRIT #6 Site 10: token registry keyed by (chainId, addr).
		tokenInfo := getTokenInfo(chainId, tokenAddr)
		if tokenInfo == nil {
			return ErrInvalidToken
		}
		if amount < tokenInfo.MinWithdrawal {
			return errors.New("below minimum withdrawal for this token")
		}
		if getGasReserve() < constants.MinGasReserve {
			return errors.New("insufficient gas reserve for ERC-20 withdrawal")
		}
	} else {
		// W4 Cluster C CRIT #7: ETH path now also enforces the gas reserve
		// floor + debits (amount + fee) from the owner. Mirror of
		// HandleUnmapETH lines 166-205.
		if getGasReserve() < constants.MinGasReserve {
			return errors.New("insufficient gas reserve")
		}
	}

	allowance := GetAllowance(params.From, caller, params.Asset)
	if allowance < amount {
		return errors.New("insufficient allowance")
	}

	// W4 Cluster C CRIT #7 (ETH path) — compute the gas fee and debit
	// (amount + fee) instead of just amount. Pre-fix, the ETH path
	// computed no fee and the vault absorbed the L1 mining cost on every
	// withdrawal. Route the addition through W2's SafeAdd64 (DO NOT
	// re-inline the +/- arithmetic — CRIT #3 owns that invariant).
	//
	// W4 Cluster A Step 3b: the ETH amount field is GWEI; fee math is wei
	// (gas units * wei/gas), then divided to gwei before SafeAdd64. Mirror
	// of HandleUnmapETH per CRIT #7 must apply gwei scaling consistently.
	totalDeduct := amount
	if params.Asset == "eth" {
		feeWei := int64(constants.ETHTransferGas * gasFeeCap)
		if params.MaxFee != "" {
			maxFee, perr := strconv.ParseInt(params.MaxFee, 10, 64)
			if perr != nil {
				return errors.New("invalid max_fee")
			}
			// HIGH #40 semantics: reject negative max_fee; max_fee=0 means
			// "no fees accepted" (no short-circuit bypass). max_fee is
			// WEI-denominated per Step 3b "gas pricing stays in wei".
			if maxFee < 0 {
				return errors.New("max_fee must be non-negative")
			}
			if feeWei > maxFee {
				return errors.New("fee exceeds max_fee")
			}
		}
		// W4 Cluster A Step 3b: convert wei fee to gwei before mixing with
		// gwei-denominated amount. Truncation = sub-gwei dust (acceptable).
		fee := feeWei / 1_000_000_000
		// CRIT #3 / W2 SafeAdd64 routing — same pattern as HandleUnmapETH.
		td, addErr := SafeAdd64(amount, fee)
		if addErr != nil {
			return errors.New("amount+fee overflow")
		}
		totalDeduct = td
		if params.DeductFee {
			totalDeduct = amount
		}
		if GetBalance(params.From, "eth") < totalDeduct {
			return errors.New("insufficient balance in owner account")
		}
	}

	// All validation passed — now mutate state
	if !DecBalance(params.From, params.Asset, totalDeduct) {
		return errors.New("insufficient balance in owner account")
	}
	SetAllowance(params.From, caller, params.Asset, allowance-amount)
	TrackWithdrawal(params.Asset, amount)

	nonce := GetPendingNonce()
	// W4 Cluster A Step 3b OUTPUT BOUNDARY: native ETH stored in gwei →
	// convert to wei before signing the L1 tx. ERC-20 amounts are
	// token-native (NOT scaled), so the ERC-20 path keeps amount as-is.
	var amountBig *big.Int
	if params.Asset == "eth" {
		amountBig = new(big.Int).Mul(big.NewInt(amount), WeiPerGwei)
	} else {
		amountBig = new(big.Int).SetInt64(amount)
	}

	var unsigned []byte
	var asset string
	var tokenAddress string
	if params.Asset == "eth" {
		unsigned = BuildETHWithdrawalTx(chainId, nonce, gasTipCap, gasFeeCap, toAddr, amountBig)
		asset = "eth"
	} else {
		unsigned = BuildERC20WithdrawalTx(chainId, nonce, gasTipCap, gasFeeCap, tokenAddr, toAddr, amountBig)
		asset = params.Asset
		tokenAddress = params.TokenAddress
		// W4 Cluster A Step 3b site #15 (CRITICAL): gas reserve is in
		// gwei. Divide wei gas cost by 1e9 before deducting — without
		// this, the reserve drains 1e9x too fast on each ERC-20
		// withdrawal and bricks all subsequent withdrawals after the
		// first. Mirror of site #14 in HandleUnmapERC20.
		gasCostWei := int64(constants.ERC20TransferGas * gasFeeCap)
		deductGasReserve(gasCostWei / 1_000_000_000)
	}

	sighash := ComputeSighash(unsigned)
	sdk.TssSignKey("primary", sighash)

	// CRIT #17 flag 3 / W4 Cluster F D-F-3: snapshot vault for unmapFrom path.
	StorePendingSpend(PendingSpend{
		Nonce:         nonce,
		Amount:        amount,
		From:          params.From,
		To:            params.To,
		Asset:         asset,
		TokenAddress:  tokenAddress,
		UnsignedTxHex: hex.EncodeToString(unsigned),
		BlockHeight:   blocklist.GetLastHeight(),
		VaultAtQueue:  "0x" + hex.EncodeToString(vaultAddress[:]),
	})
	SetPendingNonce(nonce + 1)
	return nil
}

func HandleIncreaseAllowance(params *AllowanceParams) error {
	if isPaused() {
		return errors.New("contract is paused")
	}
	env := sdk.GetEnv()
	caller := env.Caller.String()

	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil || amount <= 0 {
		return errors.New("invalid amount")
	}

	current := GetAllowance(caller, params.Spender, params.Asset)
	// W4 Cluster C: fix pre-existing lowercase typo — W2 owns SafeAdd64
	// (exported) routing; the lowercase form was a dead identifier that
	// happened to compile because the rest of the file used the exported
	// SafeAdd64 directly.
	newVal, err := SafeAdd64(current, amount)
	if err != nil {
		return errors.New("allowance overflow")
	}
	SetAllowance(caller, params.Spender, params.Asset, newVal)
	return nil
}

func HandleDecreaseAllowance(params *AllowanceParams) error {
	if isPaused() {
		return errors.New("contract is paused")
	}
	env := sdk.GetEnv()
	caller := env.Caller.String()

	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil || amount <= 0 {
		return errors.New("invalid amount")
	}

	current := GetAllowance(caller, params.Spender, params.Asset)
	newVal := current - amount
	if newVal < 0 {
		newVal = 0
	}
	SetAllowance(caller, params.Spender, params.Asset, newVal)
	return nil
}

// HandleReplaceWithdrawal — W4 Cluster E CRIT #27 (D-E-5) + HIGH #26 (D-E-7):
// add assertNotPaused() (pre-fix gap let replaceWithdrawal bypass emergency
// halt); propagate HexToAddress errors (pre-fix silently produced a 0x0
// withdrawal destination on bad ps.To).
//
// Signature unchanged — wrapped by Cluster C dispatchAdmin Operator-tactical
// (28.8K / 24h) timelock; vaultAddress comes from the contract.vault state
// slot at execute() time (current vault, not snapshot — replaceWithdrawal
// re-signs against fresh gas; the original ps.VaultAtQueue stays in state
// for confirmSpend recovery).
//
// Returns an error so the caller (main.go execute()) can route it through
// ce.CustomAbort and the L2 sees a revert reason rather than a stale-state
// success. Pre-fix calls sdk.Revert mid-flow which terminates the WASM
// directly; that pattern still works but bubbling errors is consistent
// with the rest of mapping/.
func HandleReplaceWithdrawal(vaultAddress [20]byte, chainId uint64) error {
	if isPaused() {
		return errors.New("contract is paused")
	}
	confirmedNonce := GetConfirmedNonce()
	ps := GetPendingSpend(confirmedNonce)
	if ps == nil {
		return errors.New("no pending withdrawal to replace")
	}

	// W4 Cluster E §BK / S-E-v19-1: reject legacy zero-VaultAtQueue entries
	// here as well — admin should NOT be able to inadvertently re-sign a
	// stale pre-upgrade entry via replaceWithdrawal; the explicit audit
	// trail (clearTestnetState / W0 P0) must be used instead.
	if ps.VaultAtQueue == "" || ps.VaultAtQueue == "0x0000000000000000000000000000000000000000" {
		return errors.New("legacy PendingSpend entry — use clearTestnetState or W0 P0 state-clearing procedure; contact operator")
	}

	// Rebuild with 2x gas
	header := blocklist.GetHeader(blocklist.GetLastHeight())
	if header == nil {
		return errors.New("no block headers available")
	}

	gasTipCap := uint64(4_000_000_000) // doubled
	gasFeeCap := header.BaseFeePerGas*3 + gasTipCap

	// HIGH #26 (D-E-7): propagate HexToAddress error instead of silently
	// producing a 0x0 destination. Pre-fix the underscored assignment let
	// a malformed ps.To produce a withdrawal to the zero address — the
	// signed tx was useless and the queue jammed. EH-HIGH-2 closure.
	toAddr, err := crypto.HexToAddress(ps.To)
	if err != nil {
		return errors.New("invalid withdrawal destination address")
	}
	// W4 Cluster A Step 3b OUTPUT BOUNDARY: ps.Amount is GWEI when
	// ps.Asset == "eth" (stored by HandleUnmapETH/HandleUnmapFrom which
	// run after gwei scaling). Convert to wei for the L1 unsigned tx.
	// ERC-20 amounts are token-native (NOT scaled).
	var amountBig *big.Int
	if ps.Asset == "eth" {
		amountBig = new(big.Int).Mul(big.NewInt(ps.Amount), WeiPerGwei)
	} else {
		amountBig = new(big.Int).SetInt64(ps.Amount)
	}

	var unsigned []byte
	if ps.Asset == "eth" {
		unsigned = BuildETHWithdrawalTx(chainId, confirmedNonce, gasTipCap, gasFeeCap, toAddr, amountBig)
	} else {
		// HIGH #26 audit pass: ps.TokenAddress HexToAddress error also
		// propagated (was silently discarded pre-fix).
		tokenAddr, terr := crypto.HexToAddress(ps.TokenAddress)
		if terr != nil {
			return errors.New("invalid withdrawal token address")
		}
		unsigned = BuildERC20WithdrawalTx(chainId, confirmedNonce, gasTipCap, gasFeeCap, tokenAddr, toAddr, amountBig)
	}

	sighash := ComputeSighash(unsigned)
	sdk.TssSignKey("primary", sighash)

	// Update pending spend with new signed TX
	ps.UnsignedTxHex = hex.EncodeToString(unsigned)
	StorePendingSpend(*ps)
	return nil
}

// HandleClearNonce — W4 Cluster E CRIT #27 + §11.1 (D-E-5 + D-E-6 LOCKED).
// Signature CHANGED per W4 acceptance criteria (B-E-4 + S-E-v17-2): accepts
// an L1ProofOfDrop parameter that the contract verifies BEFORE refunding L2
// balance + advancing the confirmed nonce. Pre-fix clearNonce refunded the
// L2 user and advanced the nonce unconditionally, creating a vault
// double-spend window (refund happens, original L1 tx still confirms ⇒
// vault paid AND user paid back).
//
// Flow:
//  1. assertNotPaused — pre-fix this gate was missing (CRIT #27 part 1)
//  2. Load PendingSpend; reject legacy zero-VaultAtQueue (§BK / S-E-v19-1)
//  3. Verify L1ProofOfDrop (D-E-4) — Type A reverted-receipt OR Type B
//     block-inclusion-without-tx. Reuses the receipt-trie / tx-trie MPT
//     infrastructure from HandleConfirmSpend.
//  4. Sign a 0-value self-transfer to ROLL the L1 vault nonce forward
//     (so the next withdrawal doesn't collide with the dropped nonce).
//  5. NonceAdvance(ps, 1) — CAS helper per §11.1; if expireWithdrawal
//     raced ahead, this is a no-op (returns false). Refund still applies
//     because we DEC'd via clearNonce, not expireWithdrawal.
func HandleClearNonce(vaultAddress [20]byte, chainId uint64, proof L1ProofOfDrop) error {
	if isPaused() {
		return errors.New("contract is paused")
	}
	confirmedNonce := GetConfirmedNonce()
	ps := GetPendingSpend(confirmedNonce)
	if ps == nil {
		return errors.New("no pending nonce to clear")
	}

	// §BK / S-E-v19-1: legacy zero-VaultAtQueue entries must NOT be cleared
	// via this path — admin uses clearTestnetState / W0 P0 instead, which
	// emits an explicit audit-trail event.
	if ps.VaultAtQueue == "" || ps.VaultAtQueue == "0x0000000000000000000000000000000000000000" {
		return errors.New("legacy PendingSpend entry — use clearTestnetState or W0 P0 state-clearing procedure; contact operator")
	}

	// CRIT #27 (D-E-4 LOCKED): verify L1-proof-of-drop. Either Type A
	// reverted-receipt or Type B block-inclusion-without-tx is accepted.
	// Without this gate, clearNonce can refund L2 while the original
	// L1 tx is still confirmable ⇒ vault double-spend.
	if err := verifyL1ProofOfDrop(&proof, ps, chainId); err != nil {
		return errors.New("L1-proof-of-drop verification failed: " + err.Error())
	}

	// Build 0-value self-transfer to roll L1 nonce forward
	unsigned := BuildETHWithdrawalTx(chainId, confirmedNonce, 4_000_000_000, 100_000_000_000, vaultAddress, big.NewInt(0))
	sighash := ComputeSighash(unsigned)
	sdk.TssSignKey("primary", sighash)

	// Best-effort refund: if the user's balance is at the int64 ceiling we
	// cannot credit them, but the contract MUST still advance the nonce or
	// it will jam. Only update supply when the refund actually landed,
	// otherwise balance and supply diverge.
	// CRIT #3: route supply accumulators through SafeAdd64; skip supply
	// update silently on overflow (balance has already been credited).
	if err := IncBalance(ps.From, ps.Asset, ps.Amount); err == nil {
		sup := GetSupply(ps.Asset)
		newActive, errA := SafeAdd64(sup.Active, ps.Amount)
		newUser, errU := SafeAdd64(sup.User, ps.Amount)
		if errA == nil && errU == nil {
			sup.Active = newActive
			sup.User = newUser
			SetSupply(ps.Asset, sup)
		}
	}
	DeletePendingSpend(confirmedNonce)
	// §11.1 / D-E-6: CAS advance. If expireWithdrawal won the race, this
	// returns false and we skip the SetConfirmedNonce — the other path
	// already advanced. Pending-nonce mirror keeps the dispense pointer
	// in sync regardless.
	if NonceAdvance(ps, 1) {
		SetPendingNonce(confirmedNonce + 1)
	} else {
		// Other path advanced first — re-read and pin np to current n.
		SetPendingNonce(GetConfirmedNonce())
	}

	// Audit event (matches Cluster C admin_proposal sdk.Log prefix pattern).
	sdk.Log("withdrawal_lifecycle {\"action\":\"clearNonce\"," +
		"\"nonce\":" + strconv.FormatUint(confirmedNonce, 10) + "," +
		"\"from\":\"" + ps.From + "\"," +
		"\"proof_type\":\"" + proof.Type + "\"}")
	return nil
}

// HandleExpireWithdrawal — W4 Cluster E CRIT #26 (D-E-3 LOCKED). NEW handler
// (no production code at snapshot per CRIT-FIX-MAP §3 #26). Permissionless:
// any L2 caller can submit once the EXPIRY_WINDOW has elapsed. RC cost
// deters spam; no rate limit per Q9 LOCKED. Original withdrawer can call
// BEFORE the window for convenience (early-cancel) — early-cancel ALSO
// requires an L1ProofOfDrop per S-E-1 (prevent vault-operator griefing).
//
// TSS-stuck withdrawal early-cancel exclusion (S-E-v18-3): a withdrawal
// stuck in TSS (UnsignedTxHex set but never broadcast to L1) CANNOT produce
// a Type A or Type B proof. Early-cancel is unavailable for that case —
// the original caller must wait for the EXPIRY_WINDOW. Post-window expiry
// does NOT require a proof if the caller is permissionless AND the
// EXPIRY_WINDOW has elapsed by ≥1 block (the timeout itself is the gate);
// proof is still preferred when available and is the only way for the
// original withdrawer to claim early.
//
// Signature: nonce is explicit so the caller cannot ambiguously target
// the "current confirmed" — they must name the nonce they think is stuck.
// proof is mandatory for the early-cancel path AND optional for the
// post-window expiry path (handler enforces).
func HandleExpireWithdrawal(nonce uint64, proof L1ProofOfDrop) error {
	if isPaused() {
		return errors.New("contract is paused")
	}

	confirmedNonce := GetConfirmedNonce()
	if nonce != confirmedNonce {
		return errors.New("expireWithdrawal: target nonce is not the confirmed-nonce head")
	}
	ps := GetPendingSpend(confirmedNonce)
	if ps == nil {
		return errors.New("expireWithdrawal: no pending spend at confirmed nonce")
	}

	// §AQ / v20 §BE: legacy zero-VaultAtQueue entries cannot be expired
	// through this path — operator must use clearTestnetState / W0 P0.
	if ps.VaultAtQueue == "" || ps.VaultAtQueue == "0x0000000000000000000000000000000000000000" {
		return errors.New("legacy PendingSpend entry — clear via W0 P0 state-clearing procedure; contact operator")
	}

	env := sdk.GetEnv()
	caller := env.Caller.String()
	currentHeight := env.BlockHeight
	isOriginalWithdrawer := caller == ps.From
	expiryHeight := ps.BlockHeight + constants.WithdrawalExpiryWindow
	hasExpired := currentHeight >= expiryHeight

	if !hasExpired && !isOriginalWithdrawer {
		return errors.New("expireWithdrawal: window not elapsed and caller is not original withdrawer")
	}

	// Proof handling per D-E-3:
	//  - Early-cancel (isOriginalWithdrawer && !hasExpired): proof
	//    REQUIRED per S-E-1 (prevent vault griefing on TSS-stuck or
	//    in-flight L1 txes).
	//  - Post-window expiry (hasExpired): proof OPTIONAL — the window
	//    itself is the gate. If proof is supplied, verify it for an
	//    extra safety check; if absent, allow expiry. (TSS-stuck
	//    withdrawals fall through here.)
	if !hasExpired && isOriginalWithdrawer {
		if proof.Type == "" {
			return errors.New("early-cancel requires L1-proof-of-drop; tx not yet on L1 — wait for expiry window or contact operator")
		}
		if err := verifyL1ProofOfDrop(&proof, ps, chainIdFromState()); err != nil {
			return errors.New("L1-proof-of-drop verification failed: " + err.Error())
		}
	} else if proof.Type != "" {
		// Post-window, proof supplied — opportunistically verify; abort
		// if proof is malformed so callers see a clear signal vs silent
		// accept of a wrong proof.
		if err := verifyL1ProofOfDrop(&proof, ps, chainIdFromState()); err != nil {
			return errors.New("L1-proof-of-drop verification failed: " + err.Error())
		}
	}

	// Refund L2 balance (best-effort; supply update mirrors clearNonce).
	if err := IncBalance(ps.From, ps.Asset, ps.Amount); err == nil {
		sup := GetSupply(ps.Asset)
		newActive, errA := SafeAdd64(sup.Active, ps.Amount)
		newUser, errU := SafeAdd64(sup.User, ps.Amount)
		if errA == nil && errU == nil {
			sup.Active = newActive
			sup.User = newUser
			SetSupply(ps.Asset, sup)
		}
	}

	DeletePendingSpend(confirmedNonce)
	// §11.1 / D-E-6 CAS. If clearNonce raced ahead, this returns false
	// (the other path already advanced) and we skip SetConfirmedNonce.
	if NonceAdvance(ps, 1) {
		SetPendingNonce(confirmedNonce + 1)
	} else {
		SetPendingNonce(GetConfirmedNonce())
	}

	sdk.Log("withdrawal_lifecycle {\"action\":\"expireWithdrawal\"," +
		"\"nonce\":" + strconv.FormatUint(confirmedNonce, 10) + "," +
		"\"from\":\"" + ps.From + "\"," +
		"\"caller\":\"" + caller + "\"," +
		"\"expired\":" + strconv.FormatBool(hasExpired) + "," +
		"\"proof_type\":\"" + proof.Type + "\"}")
	return nil
}

// HandleCancelMyWithdrawal — W4 Cluster E CRIT #26 (companion to
// expireWithdrawal). Only the original `From` can call this, refunds the L2
// balance, and signs a TSS self-transfer at the same nonce to ROLL the L1
// vault nonce forward (matches clearNonce's nonce-roll mechanic).
//
// Requires L1 inclusion check: the proof here is the same shape as
// expireWithdrawal — must include a Type B "block-inclusion-without-tx" or
// Type A "reverted-receipt" so the original tx cannot still confirm AFTER
// the refund. Without this gate the caller could refund themselves while
// their original L1 tx is still in the mempool, then have that tx confirm
// = double-spend from the vault.
//
// The handler is paused-guarded — even the original withdrawer cannot
// cancel during an emergency halt window (operator may be coordinating
// other recovery).
func HandleCancelMyWithdrawal(nonce uint64, proof L1ProofOfDrop, vaultAddress [20]byte, chainId uint64) error {
	if isPaused() {
		return errors.New("contract is paused")
	}
	confirmedNonce := GetConfirmedNonce()
	if nonce != confirmedNonce {
		return errors.New("cancelMyWithdrawal: target nonce is not the confirmed-nonce head")
	}
	ps := GetPendingSpend(confirmedNonce)
	if ps == nil {
		return errors.New("cancelMyWithdrawal: no pending spend at confirmed nonce")
	}

	env := sdk.GetEnv()
	caller := env.Caller.String()
	if caller != ps.From {
		return errors.New("cancelMyWithdrawal: only the original withdrawer can cancel")
	}

	// §AQ legacy reject.
	if ps.VaultAtQueue == "" || ps.VaultAtQueue == "0x0000000000000000000000000000000000000000" {
		return errors.New("legacy PendingSpend entry — clear via W0 P0 state-clearing procedure; contact operator")
	}

	// Proof MANDATORY for cancelMyWithdrawal (must NOT race original tx).
	if proof.Type == "" {
		return errors.New("cancelMyWithdrawal requires L1-proof-of-drop to prevent double-spend with in-flight L1 tx")
	}
	if err := verifyL1ProofOfDrop(&proof, ps, chainId); err != nil {
		return errors.New("L1-proof-of-drop verification failed: " + err.Error())
	}

	// TSS-sign a 0-value self-transfer to roll the L1 nonce forward.
	unsigned := BuildETHWithdrawalTx(chainId, confirmedNonce, 4_000_000_000, 100_000_000_000, vaultAddress, big.NewInt(0))
	sighash := ComputeSighash(unsigned)
	sdk.TssSignKey("primary", sighash)

	// Refund L2 balance + supply (same pattern as clearNonce).
	if err := IncBalance(ps.From, ps.Asset, ps.Amount); err == nil {
		sup := GetSupply(ps.Asset)
		newActive, errA := SafeAdd64(sup.Active, ps.Amount)
		newUser, errU := SafeAdd64(sup.User, ps.Amount)
		if errA == nil && errU == nil {
			sup.Active = newActive
			sup.User = newUser
			SetSupply(ps.Asset, sup)
		}
	}
	DeletePendingSpend(confirmedNonce)
	if NonceAdvance(ps, 1) {
		SetPendingNonce(confirmedNonce + 1)
	} else {
		SetPendingNonce(GetConfirmedNonce())
	}

	sdk.Log("withdrawal_lifecycle {\"action\":\"cancelMyWithdrawal\"," +
		"\"nonce\":" + strconv.FormatUint(confirmedNonce, 10) + "," +
		"\"from\":\"" + ps.From + "\"," +
		"\"proof_type\":\"" + proof.Type + "\"}")
	return nil
}

// chainIdFromState — internal helper. mapping/handlers.go does not have
// direct access to main.go's chainId() (no upward import); read the state
// key directly. Matches the read pattern at main.go:32-38 (ChainIdKey).
func chainIdFromState() uint64 {
	data := sdk.StateGetObject(constants.ChainIdKey)
	if data == nil {
		return 1
	}
	v, _ := strconv.ParseUint(*data, 10, 64)
	return v
}

// verifyL1ProofOfDrop — W4 Cluster E D-E-4 LOCKED. Verifies either a Type A
// reverted-receipt proof OR a Type B block-inclusion-without-tx proof.
// Both proofs are anchored against blocklist.GetHeader (which is itself
// fed by the ZK-verified light-client header chain — see the ZK
// architecture note in the W4 manifest header).
//
// Wire format spec: see types.go L1ProofOfDrop comment.
//
// Errors are returned with explicit type/index info so the bot can detect
// proof-construction bugs vs genuine mismatches in test/devnet runs.
func verifyL1ProofOfDrop(proof *L1ProofOfDrop, ps *PendingSpend, chainId uint64) error {
	if proof == nil {
		return errors.New("nil proof")
	}
	if proof.TxNonce != ps.Nonce {
		return errors.New("proof tx_nonce does not match pending spend nonce")
	}
	header := blocklist.GetHeader(proof.BlockHeight)
	if header == nil {
		return errors.New("proof block height not in observed range (header not ingested)")
	}

	switch proof.Type {
	case L1ProofTypeRevertedReceipt:
		// Type A — receipt-trie proof against header.ReceiptsRoot.
		if proof.ReceiptHex == "" || proof.ReceiptProofHex == "" {
			return errors.New("type A requires receipt_hex + receipt_proof_hex")
		}
		receiptBytes, err := hex.DecodeString(proof.ReceiptHex)
		if err != nil {
			return errors.New("invalid receipt_hex: " + err.Error())
		}
		rcptProofBytes, err := hex.DecodeString(proof.ReceiptProofHex)
		if err != nil {
			return errors.New("invalid receipt_proof_hex: " + err.Error())
		}
		rcptProof := splitProofNodes(rcptProofBytes)
		rcptKey := rlp.EncodeUint64(proof.TxIndex)
		provenReceipt, err := mpt.VerifyProof(header.ReceiptsRoot, rcptKey, rcptProof)
		if err != nil {
			return errors.New("receipt-trie proof verification failed: " + err.Error())
		}
		if !bytesEqual(provenReceipt, receiptBytes) {
			return errors.New("receipt does not match receipt-trie proof leaf")
		}
		// Parse receipt RLP; first field after typed-tx prefix is status.
		receiptToParse := receiptBytes
		if len(receiptToParse) > 0 && receiptToParse[0] <= 0x7f {
			receiptToParse = receiptToParse[1:]
		}
		items, err := rlp.DecodeList(receiptToParse)
		if err != nil || len(items) < 1 {
			return errors.New("invalid receipt RLP")
		}
		status := items[0].AsUint64()
		if status != 0 {
			return errors.New("type A proof requires status=0 (reverted); got status=" + strconv.FormatUint(status, 10))
		}
		return nil

	case L1ProofTypeBlockInclusion:
		// Type B — tx-trie proof showing the slot at TxIndex contains a
		// tx with nonce > TxNonce (vault advanced past the dropped nonce).
		if proof.TxAtIndexHex == "" || proof.TxProofHex == "" {
			return errors.New("type B requires tx_at_index_hex + tx_proof_hex")
		}
		txBytes, err := hex.DecodeString(proof.TxAtIndexHex)
		if err != nil {
			return errors.New("invalid tx_at_index_hex: " + err.Error())
		}
		txProofBytes, err := hex.DecodeString(proof.TxProofHex)
		if err != nil {
			return errors.New("invalid tx_proof_hex: " + err.Error())
		}
		txProof := splitProofNodes(txProofBytes)
		txKey := rlp.EncodeUint64(proof.TxIndex)
		provenTx, err := mpt.VerifyProof(header.TransactionsRoot, txKey, txProof)
		if err != nil {
			return errors.New("tx-trie proof verification failed: " + err.Error())
		}
		if !bytesEqual(provenTx, txBytes) {
			return errors.New("tx does not match tx-trie proof leaf")
		}
		parsed, err := parseTransaction(txBytes)
		if err != nil {
			return errors.New("failed to parse proven tx: " + err.Error())
		}
		// chainId-of-proof bound to contract chainId (Cluster B Site 1).
		if parsed.ChainId != chainId {
			return errors.New("proof tx chain id does not match contract chain id")
		}
		// Type B requires this slot's tx to have a HIGHER nonce than the
		// one being cleared — proves the vault advanced past TxNonce, so
		// the original tx at TxNonce cannot also confirm at this height.
		if parsed.Nonce <= proof.TxNonce {
			return errors.New("type B proof: tx at slot has nonce <= cleared nonce (proof does not prove drop)")
		}
		return nil

	default:
		return errors.New("unknown L1ProofOfDrop type: " + proof.Type)
	}
}

// HandleClearTestnetState — W4 Cluster E D-E-8 (v19 §AR + v20 §BG LOCKED).
// Replaces Cluster C's stub in dispatchAdmin. Chain-gated to testnet via
// the `is_testnet` state-key sentinel (set by initContract when called
// with IsTestnet=true — see main.go:117 / Cluster C's account-mapping
// initContract). On mainnet the sentinel is unset, so this aborts.
//
// Cluster B reads `is_testnet` in its OWN namespace (zk-header-verifier);
// Cluster C added the same sentinel to account-mapping's own state in
// initContract per v21 NOTABLE-1, so this read works against account-
// mapping's local namespace.
//
// Body: deletes all PendingSpend entries (constants.TxSpendsPrefix = "d-"),
// resets confirmed nonce + pending nonce to 0, clears observed-list
// (constants.ObservedBlockPrefix = "o-"). Bounded enumeration over a
// nonce-window (0 .. confirmedNonce + 1000) since sdk.StateListKeys is
// NOT confirmed available at snapshot (v19 scrutiny-E NOTABLE #3). For
// observed-list this iterates over the recent block window (0 ..
// blocklist.GetLastHeight()).
//
// admin-gating happens at dispatchAdmin via checkAdmin() / propose-execute
// (Operational class 7.2K blocks / 6h — Cluster C migration table).
func HandleClearTestnetState() error {
	// Chain gate FIRST — even if admin auth is satisfied, mainnet state
	// must NOT mutate.
	isTestnet := sdk.StateGetObject(constants.IsTestnetKey)
	if isTestnet == nil || *isTestnet != "true" {
		return errors.New("clearTestnetState forbidden on mainnet (is_testnet sentinel absent or != \"true\")")
	}

	// Bounded enumeration of PendingSpend entries.
	confirmedNonce := GetConfirmedNonce()
	pendingNonce := GetPendingNonce()
	upper := pendingNonce
	if confirmedNonce > upper {
		upper = confirmedNonce
	}
	// Add a safety margin so future-nonce entries written by a fault
	// (shouldn't happen, but defense-in-depth) are also cleared.
	upper += 1000
	psDeleted := uint64(0)
	for n := uint64(0); n <= upper; n++ {
		key := constants.TxSpendsPrefix + strconv.FormatUint(n, 10)
		if sdk.StateGetObject(key) != nil {
			sdk.StateDeleteObject(key)
			psDeleted++
		}
	}

	// Reset nonce counters.
	sdk.StateSetObject(constants.NonceConfirmedKey, "0")
	sdk.StateSetObject(constants.NoncePendingKey, "0")

	// Clear observed-list across the recent block window (bounded by
	// MaxBlockRetention so this is not unbounded work).
	lastHeight := blocklist.GetLastHeight()
	obsLower := uint64(0)
	if lastHeight > uint64(constants.MaxBlockRetention)*2 {
		obsLower = lastHeight - uint64(constants.MaxBlockRetention)*2
	}
	obsDeleted := uint64(0)
	for h := obsLower; h <= lastHeight; h++ {
		key := constants.ObservedBlockPrefix + strconv.FormatUint(h, 10)
		if sdk.StateGetObject(key) != nil {
			sdk.StateDeleteObject(key)
			obsDeleted++
		}
	}

	env := sdk.GetEnv()
	sdk.Log("clearTestnetState_executed {" +
		"\"caller\":\"" + env.Caller.String() + "\"," +
		"\"block_height\":" + strconv.FormatUint(env.BlockHeight, 10) + "," +
		"\"pending_spend_cleared\":" + strconv.FormatUint(psDeleted, 10) + "," +
		"\"observed_cleared\":" + strconv.FormatUint(obsDeleted, 10) + "}")
	return nil
}
