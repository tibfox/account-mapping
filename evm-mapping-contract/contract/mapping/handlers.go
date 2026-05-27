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

		dest := routeDeposit(sender, params.Instructions, "eth", amountInt64)

		// Gas reserve tax: bps of ETH deposits.
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

		dest := routeDeposit(sender, params.Instructions, tokenInfo.Symbol, amountInt64)
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
	gasFeeCap := header.BaseFeePerGas*2 + gasTipCap
	// W4 Cluster A Step 3b FEE BOUNDARY (wei -> gwei): the raw fee is
	// ETHTransferGas * gasFeeCap = wei. params.MaxFee semantics (HIGH #40 /
	// W2 — non-negative + maxFee=0 means "no fees accepted") stay in WEI so
	// existing operator/UI tooling that quotes max_fee in wei keeps
	// working. After the cap check, divide by 1e9 to land in gwei so the
	// SafeAdd64(amount, fee) below operates on like denominations.
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
	TrackWithdrawal("eth", amount)

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
	gasFeeCap := header.BaseFeePerGas*2 + gasTipCap
	// W4 Cluster A Step 3b: gas reserve is now gwei; convert wei gas cost
	// to gwei before deducting from the reserve accumulator.
	gasCost := int64(constants.ERC20TransferGas*gasFeeCap) / 1_000_000_000

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
	TrackWithdrawal(tokenInfo.Symbol, amount)

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

func routeDeposit(sender [20]byte, instructions []string, asset string, amount int64) string {
	did := crypto.AddressToDID(sender, 1)
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

func addGasReserve(amount int64) {
	current := getGasReserve()
	sdk.StateSetObject(constants.GasReserveKey, strconv.FormatInt(current+amount, 10))
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
	gasTipCap := uint64(2_000_000_000)
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
	if params.Asset == "eth" {
		feeWei := int64(constants.ETHTransferGas * gasFeeCap)
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
		deductGasReserve(int64(constants.ERC20TransferGas*gasFeeCap) / 1_000_000_000)
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

	gasTipCap := uint64(4_000_000_000) // doubled
	gasFeeCap := header.BaseFeePerGas*3 + gasTipCap

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

	// Best-effort refund: if the user's balance is at the int64 ceiling we cannot
	// credit them, but the contract MUST still advance the nonce or it will jam.
	if err := IncBalance(ps.From, ps.Asset, ps.Amount); err == nil {
		sup := GetSupply(ps.Asset)
		sup.Active += ps.Amount
		sup.User += ps.Amount
		SetSupply(ps.Asset, sup)
	}
	DeletePendingSpend(confirmedNonce)
	// W4 Cluster E §11.1 NonceAdvance CAS — race-safe vs HandleExpireWithdrawal.
	NonceAdvance(ps, 1)
	SetPendingNonce(GetConfirmedNonce())
	sdk.Log("withdrawal_lifecycle " + `{"action":"clearNonce","nonce":` + strconv.FormatUint(confirmedNonce, 10) + `,"from":"` + ps.From + `","proof_type":"` + proof.Type + `"}`)
	return nil
}

// HandleExpireWithdrawal — W4 Cluster E CRIT #26 (D-E-3). Permissionless after
// ps.BlockHeight + WithdrawalExpiryWindow. Pre-window callers MUST supply a
// proof; post-window opportunistic proof acceptable. Same NonceAdvance CAS.
func HandleExpireWithdrawal(nonce uint64, proof L1ProofOfDrop) error {
	if isPaused() {
		return errors.New("contract is paused")
	}
	ps := GetPendingSpend(nonce)
	if ps == nil {
		return errors.New("no pending spend at nonce")
	}
	env := sdk.GetEnv()
	expiryHeight := ps.BlockHeight + constants.WithdrawalExpiryWindow
	if env.BlockHeight < expiryHeight {
		// Pre-window: require proof.
		if proof.Type == "" {
			return errors.New("expireWithdrawal: proof required before expiry window")
		}
		if err := verifyL1ProofOfDrop(&proof, ps, 0); err != nil {
			return errors.New("L1ProofOfDrop verify failed: " + err.Error())
		}
	} else if proof.Type != "" {
		// Post-window: opportunistic verify.
		if err := verifyL1ProofOfDrop(&proof, ps, 0); err != nil {
			return errors.New("L1ProofOfDrop verify failed: " + err.Error())
		}
	}

	// Refund + advance.
	if err := IncBalance(ps.From, ps.Asset, ps.Amount); err == nil {
		sup := GetSupply(ps.Asset)
		sup.Active += ps.Amount
		sup.User += ps.Amount
		SetSupply(ps.Asset, sup)
	}
	DeletePendingSpend(nonce)
	NonceAdvance(ps, 1)
	SetPendingNonce(GetConfirmedNonce())
	sdk.Log("withdrawal_lifecycle " + `{"action":"expireWithdrawal","nonce":` + strconv.FormatUint(nonce, 10) + `,"from":"` + ps.From + `","caller":"` + env.Caller.String() + `","expired":true}`)
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

	if err := IncBalance(ps.From, ps.Asset, ps.Amount); err == nil {
		sup := GetSupply(ps.Asset)
		sup.Active += ps.Amount
		sup.User += ps.Amount
		SetSupply(ps.Asset, sup)
	}
	DeletePendingSpend(nonce)
	NonceAdvance(ps, 1)
	SetPendingNonce(GetConfirmedNonce())
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

