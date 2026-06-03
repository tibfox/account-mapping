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
	"math/big"
	"strconv"
	"strings"
)

// IsWhitelistedRelayer — W4 Cluster C CRIT #8 native-ETH frontrun mitigation
// (PARTIAL-CLOSES-AND-DEFERRALS.md item #1, v1 scope): native ETH path
// requires the caller to be a registered relayer.
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
// migrated handler with this BEFORE business logic, per W1 §D-C-9.
func AssertNotPaused() error {
	if isPaused() {
		return errors.New("contract is paused")
	}
	return nil
}

// HandleMap — W4 Cluster B CRIT #6 Sites 1+2+3+10 + W4 Cluster C CRIT #8:
// chainId threaded in for wrong-chain reject; native ETH path now also
// gated by relayer whitelist (ERC-20 stays permissionless because the
// Transfer-log proof binds depositor cryptographically).
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
		// cryptographic depositor-to-L1 binding (the L1 tx sender is not
		// the L2 caller). Gate the path on a registered relayer so a
		// rogue L2 caller cannot route someone else's deposit. ERC-20
		// path stays permissionless because the Transfer-log proof binds
		// the depositor.
		caller := sdk.GetEnv().Caller.String()
		if !IsWhitelistedRelayer(caller) {
			return errors.New("native ETH deposit: caller is not a whitelisted relayer")
		}
		// W4 Cluster B CRIT #6 Site 1: chainId passed in so VerifyETHDeposit
		// can reject wrong-chain txs before any state mutation.
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

		// Gas reserve tax: bps of ETH deposits.
		// Compute as (amount/10000)*bps + (amount%10000)*bps/10000 so we keep
		// full precision without ever producing an int64 overflow on amount*bps.
		gasTax := (amountInt64/10000)*constants.GasReserveDepositTaxBps +
			(amountInt64%10000)*constants.GasReserveDepositTaxBps/10000
		if gasTax > 0 {
			// review6 M8: surface the addGasReserve overflow so a corrupted
			// reserve never silently coexists with a successful deposit credit.
			if err := addGasReserve(gasTax); err != nil {
				return err
			}
			amountInt64 -= gasTax
		}

		if dest != "" {
			if err := IncBalance(dest, "eth", amountInt64); err != nil {
				return errors.New("balance overflow")
			}
		}
		// CRIT #3: TrackDeposit now returns on supply-accumulator overflow.
		if err := TrackDeposit("eth", amountInt64, gasTax); err != nil {
			return err
		}
		// CRIT #8 / W4 Cluster A: lock the observed slot only after the
		// deposit has been fully routed + credited + accounted. If any
		// earlier step errors, the slot stays open for the next attempt.
		MarkObserved(req.BlockHeight, txHash, uint16(req.TxIndex))
		return nil

	case "erc20":
		tokenAddr, err := crypto.HexToAddress(req.TokenAddress)
		if err != nil {
			return errors.New("invalid token address")
		}

		// W4 Cluster B CRIT #6 Site 10: token registry keyed by (chainId, addr).
		tokenInfo := getTokenInfo(chainId, tokenAddr)
		if tokenInfo == nil {
			return ErrInvalidToken
		}

		// W4 Cluster B CRIT #6 Site 2: chainId threaded so VerifyERC20Deposit
		// can read the stored header's chainId and cross-check.
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
		if err := TrackDeposit(tokenInfo.Symbol, amountInt64, 0); err != nil {
			return err
		}
		// CRIT #8 / W4 Cluster A + CRIT #14 logIndex: lock observed slot
		// only after routing + credit succeed.
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

	gasReserve := getGasReserve()
	if gasReserve < constants.MinGasReserve {
		return "", errors.New("insufficient gas reserve")
	}

	gasTipCap := uint64(2_000_000_000)                  // 2 gwei (wei units of gas pricing)
	// review6 L1/X3: route gasFeeCap and fee multiplication through bounds-
	// checked helpers. H2's oracle-trusted addBlocks can stamp arbitrary
	// BaseFeePerGas; the previous `header.BaseFeePerGas*2 + gasTipCap` and
	// `int64(ETHTransferGas * gasFeeCap)` both wrap silently past 2^63 (and
	// the int64 cast inverts sign), bypassing the maxFee cap below.
	gasFeeCap, gfcErr := computeGasFeeCap(header.BaseFeePerGas, gasTipCap)
	if gfcErr != nil {
		return "", gfcErr
	}
	// W4 Cluster A Step 3b FEE BOUNDARY (wei -> gwei): the raw fee is
	// ETHTransferGas * gasFeeCap = wei. params.MaxFee semantics (HIGH #40 /
	// W2 — non-negative + maxFee=0 means "no fees accepted") stay in WEI so
	// existing operator/UI tooling that quotes max_fee in wei keeps
	// working. After the cap check, divide by 1e9 to land in gwei so the
	// SafeAdd64(amount, fee) below operates on like denominations.
	feeWei, fwErr := SafeMulUint64(constants.ETHTransferGas, gasFeeCap)
	if fwErr != nil {
		return "", errors.New("fee overflow: " + fwErr.Error())
	}

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
		if feeWei > maxFee {
			return "", errors.New("fee exceeds max_fee")
		}
	}

	// W4 Cluster A Step 3b: convert wei fee to gwei before mixing with
	// gwei-denominated amount/balance. Truncation is acceptable dust.
	fee := feeWei / 1_000_000_000

	// Check balance BEFORE signing to prevent signed TX leak on insufficient funds.
	// CRIT #3 / W2 SafeAdd64: replace the unchecked `amount + fee` with a
	// safe-add so the totalDeduct comparison cannot wrap negative.
	totalDeduct := amount
	if !params.DeductFee {
		td, err := SafeAdd64(amount, fee)
		if err != nil {
			return "", errors.New("amount+fee overflow")
		}
		totalDeduct = td
	}
	if GetBalance(caller, "eth") < totalDeduct {
		return "", errors.New("insufficient balance")
	}

	nonce := GetPendingNonce()
	// W4 Cluster A Step 3b OUTPUT BOUNDARY (gwei -> wei): the L1 tx value
	// is wei. amount is stored in gwei; multiply by 1e9 before building
	// the unsigned tx. No overflow risk: amount * 1e9 fits in big.Int.
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
	// review6 M11: when DeductFee=true the user receives (amount-fee) on L1
	// but the vault still pays fee in gas → debit (amount) from s.Active.
	// When DeductFee=false the vault pays fee on top → debit (amount+fee).
	feeOnVault := int64(0)
	if !params.DeductFee {
		feeOnVault = fee
	}
	TrackWithdrawal("eth", amount, feeOnVault)

	// W4 Cluster F D-F-3: snapshot CURRENT vault into VaultAtQueue. When
	// confirmSpend lands, HandleConfirmSpend ecrecovers against this
	// snapshot (NOT current vault) — setVault between unmap and
	// confirmSpend no longer orphans the pending withdrawal (HIGH #29).
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
	// review6 L1/X3: gasFeeCap + fee multiplication via overflow-checked
	// helpers (see ETH-withdrawal path for rationale).
	gasFeeCap, gfcErr := computeGasFeeCap(header.BaseFeePerGas, gasTipCap)
	if gfcErr != nil {
		return "", gfcErr
	}
	// W4 Cluster A Step 3b: gas reserve is now gwei; convert wei gas cost
	// to gwei before deducting from the reserve accumulator.
	gasCostWei, gcErr := SafeMulUint64(constants.ERC20TransferGas, gasFeeCap)
	if gcErr != nil {
		return "", errors.New("erc20 gas cost overflow: " + gcErr.Error())
	}
	gasCost := gasCostWei / 1_000_000_000

	nonce := GetPendingNonce()
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
	// review6 M11: ERC-20 unmap pays L1 gas out of the contract-wide
	// gas-reserve pool (deductGasReserve below), NOT out of the user's
	// token balance — so the per-asset supply has no fee component to
	// debit here. Pass feeOnVault=0.
	TrackWithdrawal(tokenInfo.Symbol, amount, 0)

	deductGasReserve(gasCost)

	// W4 Cluster F D-F-3: snapshot vault for ERC-20 path too.
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

// HandleConfirmSpend — W4 Cluster F D-F-3 (S-F-v17-2): vaultAddress
// parameter REMOVED. The handler reads ps.VaultAtQueue directly from
// the stored PendingSpend (snapshotted at queue time). setVault between
// unmap and confirmSpend no longer orphans the pending withdrawal —
// the TSS signature targeting the OLD vault still verifies against the
// OLD vault (HIGH #29 closure).
//
// W4 Cluster E CRIT #5 + HIGH #13 (D-E-1 + D-E-2): the request carries
// 4 intent fields verified BEFORE proof work (primary HIGH #13 gate).
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
	// These 4 checks fire BEFORE any tx proof verification.
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

	// CRIT #11 site 6 (SYSTEM, REJECT) + W4 Cluster F D-F-3 (HIGH #29):
	// vault TSS-sig recovery against ps.VaultAtQueue (snapshot at unmap
	// time), NOT the current vault. setVault between unmap and confirmSpend
	// no longer orphans the pending withdrawal.
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
		// W4 Cluster A Step 3b INPUT BOUNDARY (wei -> gwei): tx value is
		// wei; ps.Amount is gwei (stored at unmap time). Divide by 1e9 to
		// compare on the same denomination — same Div semantics as
		// VerifyETHDeposit so the truncation invariant holds bit-for-bit.
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
		if err := IncBalance(ps.From, ps.Asset, ps.Amount); err == nil {
			s := GetSupply(ps.Asset)
			s.Active += ps.Amount
			s.User += ps.Amount
			SetSupply(ps.Asset, s)
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

// routeDeposit returns the L2 destination + (optionally) routes the deposit
// through the registered DEX for swap_to / asset_out instructions.
//
// review6 H9: the `deposit_to=<addr>` instruction is now HONORED ONLY for
// ERC-20 deposits, where the Transfer-log proof cryptographically binds the
// depositor — so a relayer-supplied destination is verifiable. For native
// ETH deposits, the L1 sender (recovered via ecrecover on the proven raw
// tx) is the ONLY trusted depositor signal; the caller (whitelisted L2
// relayer) MUST credit the sender's derived DID. Pre-fix, a rogue/
// compromised relayer could pass any `deposit_to=<attacker>` and redirect
// the credit, since IsWhitelistedRelayer is a coarse trust gate that does
// NOT bind to the actual L1 depositor.
//
// chainId is now threaded for the AddressToDID-vs-deposit-chain binding
// (M3 in the audit's open issues): pre-fix this was hardcoded to 1, which
// gives the wrong DID on non-mainnet L1s.
func routeDeposit(sender [20]byte, instructions []string, asset string, amount int64, chainId uint64) string {
	did := crypto.AddressToDID(sender, chainId)
	dest := did
	var swapTo, assetOut, destChain string

	// review6 H9 (adversarial-review correction): ALL instruction-driven
	// destination control is disabled for native ETH. The prior fix only
	// blocked `deposit_to=`; `swap_to=<attacker>&asset_out=<asset>` was
	// still honored, dispatching the DEX swap with `Recipient: swapTo` —
	// equivalent to redirecting the credit. A rogue/compromised
	// whitelisted relayer can choose any swap_to. params.Instructions is
	// L2-relayer-supplied (NOT extracted from L1 calldata) so the
	// depositor never consented.
	//
	// ERC-20 keeps all instruction support because the Transfer-log proof
	// cryptographically binds the L1 depositor — the relayer can't redirect.
	for _, instr := range instructions {
		if asset == "eth" {
			continue
		}
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

// getTokenInfo / RegisterToken — W4 Cluster B CRIT #6 Site 10: token
// registry now keyed by (chainId, addr) so the same ERC-20 address on
// different chains is a distinct registry entry. Pre-fix the registry
// was keyed only by addr, so a chainId pivot (or a deploy on a forked
// testnet) could silently inherit registrations.
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

// review6 M8: unchecked int64 addition overflowed the gas-reserve accumulator
// to a negative value when called with large positive `amount` (or via repeat
// owner top-ups). Route the add through SafeAdd64; on overflow, leave the
// reserve unchanged and surface the failure as a logged abort so the caller
// can retry with a smaller amount rather than silently corrupting state.
func addGasReserve(amount int64) error {
	current := getGasReserve()
	newVal, err := SafeAdd64(current, amount)
	if err != nil {
		return errors.New("addGasReserve overflow: " + err.Error())
	}
	sdk.StateSetObject(constants.GasReserveKey, strconv.FormatInt(newVal, 10))
	return nil
}

func deductGasReserve(amount int64) {
	current := getGasReserve()
	newVal := current - amount
	if newVal < 0 {
		newVal = 0
	}
	sdk.StateSetObject(constants.GasReserveKey, strconv.FormatInt(newVal, 10))
}


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

	// W4 Cluster C CRIT #7: compute gas pricing up front for BOTH paths so
	// the reserve floor check applies to ETH-path withdrawals (pre-fix the
	// floor check was only run on the ERC-20 path; the ETH path skipped it
	// entirely, drained the vault, and never deducted fees from the owner).
	// review6 L1/X3: route gasFeeCap through computeGasFeeCap.
	gasTipCap := uint64(2_000_000_000)
	gasFeeCap, gfcErr := computeGasFeeCap(header.BaseFeePerGas, gasTipCap)
	if gfcErr != nil {
		return gfcErr
	}

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
		// floor + debits (amount + fee) from the owner.
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
	// withdrawal. Route the addition through SafeAdd64 (W2 CRIT #3).
	totalDeduct := amount
	// review6 M11: ethFeeOnVault tracks the L1 gas portion that the vault
	// pays out of the user's balance (only non-zero on the ETH-asset path
	// when DeductFee=false). Threaded through to TrackWithdrawal so
	// s.Active mirrors the actual vault debit.
	ethFeeOnVault := int64(0)
	if params.Asset == "eth" {
		// review6 L1/X3: SafeMulUint64 catches overflow on (gas * gasFeeCap)
		// before the int64 cast can flip the sign and bypass maxFee.
		feeWei, fwErr := SafeMulUint64(constants.ETHTransferGas, gasFeeCap)
		if fwErr != nil {
			return errors.New("fee overflow: " + fwErr.Error())
		}
		if params.MaxFee != "" {
			maxFee, perr := strconv.ParseInt(params.MaxFee, 10, 64)
			if perr != nil {
				return errors.New("invalid max_fee")
			}
			if maxFee < 0 {
				return errors.New("max_fee must be non-negative")
			}
			if feeWei > maxFee {
				return errors.New("fee exceeds max_fee")
			}
		}
		// Step 3b: gwei conversion before SafeAdd64.
		fee := feeWei / 1_000_000_000
		td, addErr := SafeAdd64(amount, fee)
		if addErr != nil {
			return errors.New("amount+fee overflow")
		}
		totalDeduct = td
		if params.DeductFee {
			totalDeduct = amount
		} else {
			ethFeeOnVault = fee
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
	// review6 M11: feed feeOnVault into supply tracking so s.Active doesn't
	// drift upward over deposit/withdraw cycles. ERC-20 path is fee-on-
	// gas-reserve (separate pool) so feeOnVault=0.
	TrackWithdrawal(params.Asset, amount, ethFeeOnVault)

	nonce := GetPendingNonce()

	var unsigned []byte
	var asset string
	var tokenAddress string
	if params.Asset == "eth" {
		// W4 Cluster A Step 3b: ETH amount is gwei; convert to wei for L1 tx.
		amountBig := new(big.Int).Mul(big.NewInt(amount), WeiPerGwei)
		unsigned = BuildETHWithdrawalTx(chainId, nonce, gasTipCap, gasFeeCap, toAddr, amountBig)
		asset = "eth"
	} else {
		// ERC-20: token-native units (USDC=6 decimals); no gwei scaling.
		amountBig := new(big.Int).SetInt64(amount)
		unsigned = BuildERC20WithdrawalTx(chainId, nonce, gasTipCap, gasFeeCap, tokenAddr, toAddr, amountBig)
		asset = params.Asset
		tokenAddress = params.TokenAddress
		// W4 Cluster A Step 3b: gas reserve gwei; convert wei -> gwei.
		// review6 L1/X3: SafeMulUint64 prevents the int64 cast from inverting
		// sign and crediting (negative) reserves; on overflow we abort the
		// withdrawal before any state mutates.
		gasCostWei, gcErr := SafeMulUint64(constants.ERC20TransferGas, gasFeeCap)
		if gcErr != nil {
			return errors.New("erc20 gas cost overflow: " + gcErr.Error())
		}
		deductGasReserve(gasCostWei / 1_000_000_000)
	}

	sighash := ComputeSighash(unsigned)
	sdk.TssSignKey("primary", sighash)

	// W4 Cluster F D-F-3: snapshot vault for HandleUnmapFrom path.
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

// HandleReplaceWithdrawal — W4 Cluster E CRIT #27 + HIGH #26:
//   - now returns error (was void with mid-flow sdk.Revert pre-fix);
//   - assertNotPaused gate (CRIT #27 pause-guard gap closure);
//   - HexToAddress error propagated instead of silent 0x0 (HIGH #26).
func HandleReplaceWithdrawal(vaultAddress [20]byte, chainId uint64) error {
	if isPaused() {
		return errors.New("contract is paused")
	}
	confirmedNonce := GetConfirmedNonce()
	ps := GetPendingSpend(confirmedNonce)
	if ps == nil {
		return errors.New("no pending withdrawal to replace")
	}

	// Rebuild with 2x gas
	header := blocklist.GetHeader(blocklist.GetLastHeight())
	if header == nil {
		return errors.New("no block headers available")
	}

	// review6 L1/X3 (adversarial-review correction): HandleReplaceWithdrawal
	// was the 5th gas-fee site the audit's "four sites" missed. Route the
	// (3x baseFee + tip) calculation through the same overflow-checked
	// helper used in HandleUnmapETH / HandleUnmapERC20 / HandleUnmapFrom.
	// Dormant after H2 closed the oracle-fed-header surface, but the
	// arithmetic should still be bounded for defense-in-depth.
	gasTipCap := uint64(4_000_000_000) // doubled
	gasFeeCap, gfcErr := computeReplaceGasFeeCap(header.BaseFeePerGas, gasTipCap)
	if gfcErr != nil {
		return gfcErr
	}

	// HIGH #26: surface destination-address parse errors instead of silently
	// signing a tx to the zero address.
	toAddr, herr := crypto.HexToAddress(ps.To)
	if herr != nil {
		return errors.New("pending spend destination parse failed: " + herr.Error())
	}

	var unsigned []byte
	if ps.Asset == "eth" {
		// W4 Cluster A Step 3b: ETH amount is gwei; convert to wei for L1 tx.
		amountBig := new(big.Int).Mul(big.NewInt(ps.Amount), WeiPerGwei)
		unsigned = BuildETHWithdrawalTx(chainId, confirmedNonce, gasTipCap, gasFeeCap, toAddr, amountBig)
	} else {
		amountBig := new(big.Int).SetInt64(ps.Amount)
		tokenAddr, terr := crypto.HexToAddress(ps.TokenAddress)
		if terr != nil {
			return errors.New("pending spend token address parse failed: " + terr.Error())
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

// HandleClearNonce — W4 Cluster E CRIT #27 (B-E-4 + S-E-v17-2):
//   - takes an L1ProofOfDrop so the proof field is reachable from the
//     propose/execute payload (pre-fix the wasmexport ignored its
//     input entirely with `_ *string`);
//   - assertNotPaused gate (CRIT #27);
//   - returns error instead of mid-flow sdk.Revert.
func HandleClearNonce(vaultAddress [20]byte, chainId uint64, proof L1ProofOfDrop) error {
	if isPaused() {
		return errors.New("contract is paused")
	}
	confirmedNonce := GetConfirmedNonce()
	ps := GetPendingSpend(confirmedNonce)
	if ps == nil {
		return errors.New("no pending nonce to clear")
	}
	// L1-proof-of-drop gate: clearNonce previously had no proof anchor at
	// all. Verify the proof binds the cleared nonce to a reverted-receipt
	// or block-inclusion-without-tx event on L1.
	if err := verifyL1ProofOfDrop(&proof, ps, chainId); err != nil {
		return errors.New("L1ProofOfDrop verify failed: " + err.Error())
	}

	// Build 0-value self-transfer to advance nonce
	unsigned := BuildETHWithdrawalTx(chainId, confirmedNonce, 4_000_000_000, 100_000_000_000, vaultAddress, big.NewInt(0))
	sighash := ComputeSighash(unsigned)
	sdk.TssSignKey("primary", sighash)

	// review6 X2 (adversarial-review correction): hard-fail if the refund
	// cannot be credited. Pre-fix the contract silently swallowed an
	// IncBalance failure (e.g. int64-max overflow on the user's balance)
	// then advanced the nonce + deleted the PendingSpend unconditionally —
	// silent user-fund loss. With the hard-fail, the operation aborts
	// before any state mutates; the user must reduce their existing
	// balance (transfer out) before retrying clearNonce / expire / cancel.
	// SafeAdd64 covers the supply accumulators (L2 piece) on the success
	// path; on failure neither balance nor supply moves and the nonce
	// stays put, preserving the invariant that "state advanced => user
	// was refunded".
	if err := IncBalance(ps.From, ps.Asset, ps.Amount); err != nil {
		return errors.New("clearNonce: refund would overflow user balance — reduce existing balance first (" + err.Error() + ")")
	}
	sup := GetSupply(ps.Asset)
	newActive, errA := SafeAdd64(sup.Active, ps.Amount)
	if errA != nil {
		return errors.New("clearNonce: supply.Active overflow — refund would corrupt accounting")
	}
	newUser, errU := SafeAdd64(sup.User, ps.Amount)
	if errU != nil {
		return errors.New("clearNonce: supply.User overflow — refund would corrupt accounting")
	}
	sup.Active = newActive
	sup.User = newUser
	SetSupply(ps.Asset, sup)
	// bug #8: NonceAdvance re-reads the PendingSpend and no-ops once it's
	// deleted, so advance BEFORE DeletePendingSpend (race-safe vs HandleExpireWithdrawal).
	NonceAdvance(ps, 1)
	SetPendingNonce(GetConfirmedNonce())
	DeletePendingSpend(confirmedNonce)
	sdk.Log("withdrawal_lifecycle " + `{"action":"clearNonce","nonce":` + strconv.FormatUint(confirmedNonce, 10) + `,"from":"` + ps.From + `","proof_type":"` + proof.Type + `"}`)
	return nil
}

// HandleExpireWithdrawal — W4 Cluster E CRIT #26 (D-E-3). Permissionless after
// ps.BlockHeight + WithdrawalExpiryWindow. Pre-window callers MUST supply a
// proof; post-window opportunistic proof acceptable. Same NonceAdvance CAS.
func HandleExpireWithdrawal(nonce uint64, proof L1ProofOfDrop, chainId uint64) error {
	if isPaused() {
		return errors.New("contract is paused")
	}
	// F3a (restore review5): only the confirmed-head nonce is expirable. With
	// the single-outstanding-withdrawal invariant (HasPendingWithdrawal gates
	// new unmaps), the head is the only live PendingSpend; rejecting non-head
	// nonces prevents deleting a non-head entry without advancing the head.
	confirmedNonce := GetConfirmedNonce()
	if nonce != confirmedNonce {
		return errors.New("expireWithdrawal: target nonce is not the confirmed-nonce head")
	}
	ps := GetPendingSpend(confirmedNonce)
	if ps == nil {
		return errors.New("no pending spend at nonce")
	}
	if ps.VaultAtQueue == "" || ps.VaultAtQueue == "0x0000000000000000000000000000000000000000" {
		return errors.New("legacy PendingSpend entry — clear via admin clearNonce/state procedure")
	}

	env := sdk.GetEnv()
	caller := env.Caller.String()
	isOriginalWithdrawer := caller == ps.From
	expiryHeight := ps.BlockHeight + constants.WithdrawalExpiryWindow
	hasExpired := env.BlockHeight >= expiryHeight

	// Pre-window: only the original withdrawer may early-cancel. Post-window:
	// anyone may expire (the window is the gate for WHO).
	if !hasExpired && !isOriginalWithdrawer {
		return errors.New("expireWithdrawal: window not elapsed and caller is not original withdrawer")
	}

	// F3b: an L1-proof-of-drop is MANDATORY in ALL cases — a refund is only
	// issued against cryptographic proof that the L1 withdrawal did NOT send
	// funds (type A: reverted receipt; type B: the nonce slot was consumed by
	// a different tx). Previously the post-window path skipped the proof
	// entirely, so a withdrawal that SUCCEEDED on L1 but whose confirmSpend
	// lagged could be refunded on L2 (double-spend). The window governs only
	// WHO may call, never WHETHER proof is required.
	//
	// NOTE (follow-up, not this fix): a genuinely-stuck/never-broadcast
	// withdrawal (vault nonce never advanced) cannot produce a type-A/B proof
	// and therefore cannot be expired here — it requires a dedicated
	// TSS-nonce-roll recovery (consume slot N with a 0-value self-transfer,
	// THEN refund) so the original tx becomes permanently unmineable. A naive
	// "nonce-not-advanced" account proof is NOT safe: an in-flight tx can mine
	// after any proof block, reopening the double-spend. Tracked separately.
	if proof.Type == "" {
		return errors.New("expireWithdrawal: L1-proof-of-drop is mandatory (proves the L1 tx did not execute)")
	}
	if err := verifyL1ProofOfDrop(&proof, ps, chainId); err != nil {
		return errors.New("L1ProofOfDrop verify failed: " + err.Error())
	}

	// review6 X2 (adversarial-review correction): hard-fail if the refund
	// cannot be credited. Pre-fix the if-err-nil swallowed an IncBalance
	// failure and advanced the nonce + deleted the PendingSpend regardless
	// — silent user-fund loss class. With the hard-fail, the operation
	// aborts before any state mutates; user must reduce their existing
	// balance before retrying.
	if err := IncBalance(ps.From, ps.Asset, ps.Amount); err != nil {
		return errors.New("expireWithdrawal: refund would overflow user balance — reduce existing balance first (" + err.Error() + ")")
	}
	sup := GetSupply(ps.Asset)
	newActive, errA := SafeAdd64(sup.Active, ps.Amount)
	if errA != nil {
		return errors.New("expireWithdrawal: supply.Active overflow — refund would corrupt accounting")
	}
	newUser, errU := SafeAdd64(sup.User, ps.Amount)
	if errU != nil {
		return errors.New("expireWithdrawal: supply.User overflow — refund would corrupt accounting")
	}
	sup.Active = newActive
	sup.User = newUser
	SetSupply(ps.Asset, sup)
	// bug #8: advance BEFORE delete (NonceAdvance no-ops once PendingSpend gone).
	NonceAdvance(ps, 1)
	SetPendingNonce(GetConfirmedNonce())
	DeletePendingSpend(nonce)
	sdk.Log("withdrawal_lifecycle " + `{"action":"expireWithdrawal","nonce":` + strconv.FormatUint(nonce, 10) + `,"from":"` + ps.From + `","caller":"` + caller + `","proof_type":"` + proof.Type + `"}`)
	return nil
}

// HandleCancelMyWithdrawal — W4 Cluster E CRIT #26 companion. Only ps.From
// can call; proof MANDATORY.
func HandleCancelMyWithdrawal(nonce uint64, proof L1ProofOfDrop, vaultAddress [20]byte, chainId uint64) error {
	if isPaused() {
		return errors.New("contract is paused")
	}
	ps := GetPendingSpend(nonce)
	if ps == nil {
		return errors.New("no pending spend at nonce")
	}
	env := sdk.GetEnv()
	if env.Caller.String() != ps.From {
		return errors.New("cancelMyWithdrawal: only the original withdrawer can cancel")
	}
	if proof.Type == "" {
		return errors.New("cancelMyWithdrawal: proof MANDATORY")
	}
	if err := verifyL1ProofOfDrop(&proof, ps, chainId); err != nil {
		return errors.New("L1ProofOfDrop verify failed: " + err.Error())
	}
	// TSS-sign self-transfer to roll the L1 vault nonce.
	unsigned := BuildETHWithdrawalTx(chainId, nonce, 4_000_000_000, 100_000_000_000, vaultAddress, big.NewInt(0))
	sighash := ComputeSighash(unsigned)
	sdk.TssSignKey("primary", sighash)

	// review6 X2 (adversarial-review correction): hard-fail on refund
	// failure across all three escape-hatch handlers. Matches the new
	// HandleExpireWithdrawal / HandleClearNonce pattern.
	if err := IncBalance(ps.From, ps.Asset, ps.Amount); err != nil {
		return errors.New("cancelMyWithdrawal: refund would overflow user balance — reduce existing balance first (" + err.Error() + ")")
	}
	sup := GetSupply(ps.Asset)
	newActive, errA := SafeAdd64(sup.Active, ps.Amount)
	if errA != nil {
		return errors.New("cancelMyWithdrawal: supply.Active overflow — refund would corrupt accounting")
	}
	newUser, errU := SafeAdd64(sup.User, ps.Amount)
	if errU != nil {
		return errors.New("cancelMyWithdrawal: supply.User overflow — refund would corrupt accounting")
	}
	sup.Active = newActive
	sup.User = newUser
	SetSupply(ps.Asset, sup)
	// bug #8: advance BEFORE delete (NonceAdvance no-ops once PendingSpend gone).
	NonceAdvance(ps, 1)
	SetPendingNonce(GetConfirmedNonce())
	DeletePendingSpend(nonce)
	sdk.Log("withdrawal_lifecycle " + `{"action":"cancelMyWithdrawal","nonce":` + strconv.FormatUint(nonce, 10) + `,"from":"` + ps.From + `","proof_type":"` + proof.Type + `"}`)
	return nil
}

// HandleClearTestnetState — W4 Cluster E D-E-8 (chain-gated to testnet via
// is_testnet state-key sentinel; mainnet redirects unset / != "true" reject).
func HandleClearTestnetState() error {
	isTestnet := sdk.StateGetObject(constants.IsTestnetKey)
	if isTestnet == nil || *isTestnet != "true" {
		return errors.New("clearTestnetState: not a testnet contract")
	}
	// Clear pending spends, nonces, and observed-list within MaxBlockRetention*2.
	confirmed := GetConfirmedNonce()
	pending := GetPendingNonce()
	for n := confirmed; n <= pending; n++ {
		DeletePendingSpend(n)
	}
	sdk.StateDeleteObject(constants.NonceConfirmedKey)
	sdk.StateDeleteObject(constants.NoncePendingKey)
	// Observed-list cleanup window.
	lastH := blocklist.GetLastHeight()
	startH := uint64(0)
	if lastH > uint64(constants.MaxBlockRetention*2) {
		startH = lastH - uint64(constants.MaxBlockRetention*2)
	}
	for h := startH; h <= lastH; h++ {
		sdk.StateDeleteObject(constants.ObservedBlockPrefix + strconv.FormatUint(h, 10))
	}
	sdk.Log("clearTestnetState_executed " + `{"action":"clearTestnetState","block_height":` + strconv.FormatUint(lastH, 10) + `}`)
	return nil
}

// verifyL1ProofOfDrop — W4 Cluster E D-E-4 LOCKED. Type A: receipt-trie MPT
// proof + status==0. Type B: tx-trie MPT proof + parsed.Nonce > TxNonce
// (vault advanced past cleared nonce). Both: blocklist.GetHeader forces
// block to be ZK-anchored; proof.TxNonce == ps.Nonce.
func verifyL1ProofOfDrop(proof *L1ProofOfDrop, ps *PendingSpend, chainId uint64) error {
	if proof == nil || ps == nil {
		return errors.New("nil proof or pending spend")
	}
	if proof.TxNonce != ps.Nonce {
		return errors.New("proof tx_nonce does not match pending spend nonce")
	}
	header := blocklist.GetHeader(proof.BlockHeight)
	if header == nil {
		return errors.New("proof block not anchored")
	}
	switch proof.Type {
	case L1ProofTypeRevertedReceipt:
		// review6 H10: Type A now requires BOTH (a) a receipt-trie proof
		// showing status=0 at TxIndex AND (b) a tx-trie proof showing the
		// raw tx at the same TxIndex with parsed.Nonce == proof.TxNonce
		// AND parsed.From == ps.VaultAtQueue. Pre-fix, only (a) was checked
		// and proof.TxNonce was a user-supplied claim unbound to the proven
		// receipt — an attacker could prove ANY reverted receipt and claim
		// ANY nonce, double-spending withdrawals on every proof-required
		// path (clearNonce, cancelMyWithdrawal, pre-window expireWithdrawal).
		// Now the tx-trie proof cryptographically binds the nonce + sender
		// to the proven L1 slot, closing the forgery class.
		receiptBytes, err := hex.DecodeString(proof.ReceiptHex)
		if err != nil {
			return errors.New("invalid receipt_hex")
		}
		proofBytes, err := hex.DecodeString(proof.ReceiptProofHex)
		if err != nil {
			return errors.New("invalid receipt_proof_hex")
		}
		proven, err := mpt.VerifyProof(header.ReceiptsRoot, mpt.RLPEncodeKey(proof.TxIndex), splitProofNodes(proofBytes))
		if err != nil {
			return errors.New("receipt proof verification failed")
		}
		if !bytesEqual(proven, receiptBytes) {
			return errors.New("receipt does not match proof")
		}
		// Parse status: receipt RLP first field after type-byte strip is status.
		data := receiptBytes
		if len(data) > 0 && data[0] <= 0x7f {
			data = data[1:]
		}
		items, err := rlp.DecodeList(data)
		if err != nil || len(items) < 1 {
			return errors.New("malformed receipt")
		}
		if items[0].AsUint64() != 0 {
			return errors.New("receipt status != 0 — tx not reverted")
		}
		// review6 H10: bind the proven receipt to the L1 tx via the
		// transactions trie at the SAME TxIndex. The raw tx carries the
		// nonce + sender; verifying it lets us reject forged proofs where
		// proof.TxNonce is decoupled from the proven L1 slot.
		txBytes, err := hex.DecodeString(proof.TxAtIndexHex)
		if err != nil || len(txBytes) == 0 {
			return errors.New("Type A requires tx_at_index_hex bound to the proven receipt")
		}
		txProofBytes, err := hex.DecodeString(proof.TxProofHex)
		if err != nil || len(txProofBytes) == 0 {
			return errors.New("Type A requires tx_proof_hex for nonce binding")
		}
		provenTx, err := mpt.VerifyProof(header.TransactionsRoot, mpt.RLPEncodeKey(proof.TxIndex), splitProofNodes(txProofBytes))
		if err != nil {
			return errors.New("tx proof verification failed")
		}
		if !bytesEqual(provenTx, txBytes) {
			return errors.New("tx does not match proof")
		}
		parsed, err := parseTransaction(txBytes)
		if err != nil {
			return errors.New("failed to parse proven tx: " + err.Error())
		}
		if chainId != 0 && parsed.ChainId != chainId {
			return errors.New("proof tx chain id mismatch")
		}
		if parsed.Nonce != proof.TxNonce {
			return errors.New("proven tx nonce does not match proof.tx_nonce — bind failed")
		}
		// Verify the proven tx originated from the snapshotted vault. Without
		// this, an attacker could prove a reverted receipt + a tx from any
		// OTHER address that happened to share TxIndex in some block — the
		// nonce would match by coincidence and the bind would silently pass.
		expectedVault := strings.ToLower(ps.VaultAtQueue)
		if !strings.HasPrefix(expectedVault, "0x") {
			expectedVault = "0x" + expectedVault
		}
		sighash := computeTxSighash(txBytes, parsed)
		recoveryV := byte(27 + parsed.V)
		rPadded := padTo32(parsed.R)
		sPadded := padTo32(parsed.S)
		sender, err := crypto.EcrecoverCanonical(sighash, recoveryV, rPadded, sPadded)
		if err != nil {
			return errors.New("ecrecover on proven tx failed: " + err.Error())
		}
		senderHex := "0x" + hex.EncodeToString(sender[:])
		if !strings.EqualFold(senderHex, expectedVault) {
			return errors.New("proven tx sender does not match vault-at-queue — wrong-vault proof")
		}
		return nil
	case L1ProofTypeBlockInclusion:
		txBytes, err := hex.DecodeString(proof.TxAtIndexHex)
		if err != nil {
			return errors.New("invalid tx_at_index_hex")
		}
		proofBytes, err := hex.DecodeString(proof.TxProofHex)
		if err != nil {
			return errors.New("invalid tx_proof_hex")
		}
		proven, err := mpt.VerifyProof(header.TransactionsRoot, mpt.RLPEncodeKey(proof.TxIndex), splitProofNodes(proofBytes))
		if err != nil {
			return errors.New("tx proof verification failed")
		}
		if !bytesEqual(proven, txBytes) {
			return errors.New("tx does not match proof")
		}
		parsed, err := parseTransaction(txBytes)
		if err != nil {
			return errors.New("failed to parse proven tx: " + err.Error())
		}
		if chainId != 0 && parsed.ChainId != chainId {
			return errors.New("proof tx chain id mismatch")
		}
		if parsed.Nonce <= proof.TxNonce {
			return errors.New("proof tx nonce does not exceed cleared nonce — vault has not advanced")
		}
		return nil
	default:
		return errors.New("unknown L1ProofOfDrop type: " + proof.Type)
	}
}

// ConfirmSpendSchemaJSON — W4 Cluster E CRIT #5 (D-E-1) canonical wire
// schema for the ConfirmSpendRequest payload (10 top-level fields).
const ConfirmSpendSchemaJSON = `{"version":1,"type":"ConfirmSpendRequest","fields":[` +
	`{"name":"block_height","type":"uint64"},` +
	`{"name":"tx_index","type":"uint64"},` +
	`{"name":"tx_hex","type":"hex"},` +
	`{"name":"tx_proof_hex","type":"hex"},` +
	`{"name":"receipt_hex","type":"hex"},` +
	`{"name":"receipt_proof_hex","type":"hex"},` +
	`{"name":"intent_nonce","type":"uint64"},` +
	`{"name":"intent_to","type":"string"},` +
	`{"name":"intent_amount","type":"int64"},` +
	`{"name":"intent_asset","type":"string"}` +
	`]}`

