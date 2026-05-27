package mapping

import (
	"encoding/hex"
	"encoding/json"
	"evm-mapping-contract/contract/abi"
	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
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
		return ce.NewContractError(ce.ErrInitialization, "contract is paused")
	}
	return nil
}

// HandleMap — W4 Cluster B CRIT #6 Sites 1+2+3+10 + W4 Cluster C CRIT #8:
// chainId threaded in for wrong-chain reject; native ETH path now also
// gated by relayer whitelist (ERC-20 stays permissionless because the
// Transfer-log proof binds depositor cryptographically).
func HandleMap(params *MapParams, vaultAddress [20]byte, chainId uint64) error {
	if isPaused() {
		return ce.NewContractError(ce.ErrIntent, "contract is paused")
	}
	if vaultAddress == ([20]byte{}) {
		return ce.NewContractError(ce.ErrInitialization, "vault address not configured")
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
			return ce.NewContractError(ce.ErrAuth, "native ETH deposit: caller is not a whitelisted relayer")
		}
		// W4 Cluster B CRIT #6 Site 1: chainId passed in so VerifyETHDeposit
		// can reject wrong-chain txs before any state mutation.
		sender, amountBytes, txHash, err := VerifyETHDeposit(req, vaultAddress, chainId)
		if err != nil {
			return err
		}

		amount := new(big.Int).SetBytes(amountBytes)
		if amount.Sign() <= 0 {
			return ce.NewContractError(ce.ErrInput, "deposit amount must be positive")
		}
		if !amount.IsInt64() || amount.Int64() <= 0 {
			return ce.NewContractError(ce.ErrArithmetic, "deposit amount exceeds safe int64 range")
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
				return ce.WrapContractError(ce.ErrArithmetic, err, "balance overflow")
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
			return ce.Prepend(err, "token address")
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
			return ce.NewContractError(ce.ErrArithmetic, "deposit amount invalid or exceeds safe range")
		}
		amountInt64 := amount.Int64()

		dest := routeDeposit(sender, params.Instructions, tokenInfo.Symbol, amountInt64)
		if dest != "" {
			if err := IncBalance(dest, tokenInfo.Symbol, amountInt64); err != nil {
				return ce.WrapContractError(ce.ErrArithmetic, err, "balance overflow")
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
		return ce.NewContractError(ce.ErrInput, "deposit_type must be 'eth' or 'erc20'")
	}
}

func HandleUnmapETH(params *TransferParams, vaultAddress [20]byte, chainId uint64) (string, error) {
	if isPaused() {
		return "", ce.NewContractError(ce.ErrIntent, "contract is paused")
	}
	if HasPendingWithdrawal() {
		return "", ce.NewContractError(ce.ErrIntent, "withdrawal pending: wait for confirmation")
	}

	env := sdk.GetEnv()
	caller := env.Caller.String()

	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil || amount <= 0 {
		return "", ce.NewContractError(ce.ErrInput, "invalid amount")
	}
	if amount < constants.MinETHWithdrawal {
		return "", ce.NewContractError(ce.ErrIntent, "below minimum ETH withdrawal")
	}

	toAddr, err := crypto.HexToAddress(params.To)
	if err != nil {
		return "", ce.Prepend(err, "'to' address")
	}
	// review2 #44: the zero address parses as a valid [20]byte; a
	// TSS-signed withdrawal to 0x000…0 burns the funds irrecoverably.
	if toAddr == ([20]byte{}) {
		return "", ce.NewContractError(ce.ErrInput, "refusing withdrawal to zero address")
	}

	header := blocklist.GetHeader(blocklist.GetLastHeight())
	if header == nil {
		return "", ce.NewContractError(ce.ErrInitialization, "no block headers available")
	}

	gasReserve := getGasReserve()
	if gasReserve < constants.MinGasReserve {
		return "", ce.NewContractError(ce.ErrBalance, "insufficient gas reserve")
	}

	gasTipCap := uint64(2_000_000_000) // 2 gwei
	// review2 HIGH #16: checked arithmetic — a negative (wrapped) fee here
	// inflated the user's balance instead of debiting it.
	gasFeeCap, feeWei, feeErr := safeGasFee(constants.ETHTransferGas, header.BaseFeePerGas, 2, gasTipCap)
	if feeErr != nil {
		return "", ce.NewContractError(ce.ErrArithmetic, "gas fee computation overflow")
	}

	if params.MaxFee != "" {
		maxFee, err := strconv.ParseInt(params.MaxFee, 10, 64)
		if err != nil {
			return "", ce.NewContractError(ce.ErrInput, "invalid max_fee")
		}
		// HIGH #40: reject negative max_fee instead of silently disabling the cap.
		if maxFee < 0 {
			return "", ce.NewContractError(ce.ErrInput, "max_fee must be non-negative")
		}
		// HIGH #40: maxFee=0 must mean "no fees accepted" — drop the
		// previous `maxFee > 0 &&` short-circuit so a zero cap can reject
		// a positive computed fee. maxFee is quoted in WEI, so compare feeWei.
		if feeWei > maxFee {
			return "", ce.NewContractError(ce.ErrInput, "fee exceeds max_fee")
		}
	}

	// W4-A Step 3b: safeGasFee returns the fee in WEI; convert to gwei before
	// mixing with the gwei-denominated amount/balance. Sub-gwei dust truncates.
	fee := feeWei / 1_000_000_000

	// Check balance BEFORE signing to prevent signed TX leak on insufficient funds.
	// CRIT #3 / W2 SafeAdd64: replace the unchecked `amount + fee` with a
	// safe-add so the totalDeduct comparison cannot wrap negative.
	totalDeduct := amount
	if !params.DeductFee {
		td, err := SafeAdd64(amount, fee)
		if err != nil {
			return "", ce.NewContractError(ce.ErrArithmetic, "amount+fee overflow")
		}
		totalDeduct = td
	}
	if GetBalance(caller, "eth") < totalDeduct {
		return "", ce.NewContractError(ce.ErrBalance, "insufficient balance")
	}

	nonce := GetPendingNonce()
	// W4-A Step 3b: amount is gwei; the L1 tx value is wei, so scale up.
	amountBig := new(big.Int).Mul(big.NewInt(amount), WeiPerGwei)
	unsigned := BuildETHWithdrawalTx(chainId, nonce, gasTipCap, gasFeeCap, toAddr, amountBig)
	sighash := ComputeSighash(unsigned)

	if err := requireTssKey(); err != nil {
		return "", err
	}
	sdk.TssSignKey("primary", sighash)

	if !DecBalance(caller, "eth", totalDeduct) {
		return "", ce.NewContractError(ce.ErrBalance, "insufficient balance")
	}
	// review2 #76: the user balance was debited totalDeduct (amount+fee)
	// but TrackWithdrawal only reduced supply by `amount`, so Supply.User
	// drifted above the true sum of user balances by `fee` every
	// withdrawal. Reduce User by the full debit, Active by the bridged
	// amount, and book the fee as protocol Fee so the invariant
	// Supply.User == Σ user balances holds.
	{
		s := GetSupply("eth")
		s.Active -= amount
		if s.Active < 0 {
			s.Active = 0
		}
		s.User -= totalDeduct
		if s.User < 0 {
			s.User = 0
		}
		s.Fee += totalDeduct - amount
		SetSupply("eth", s)
	}

	// Store pending spend
	StorePendingSpend(PendingSpend{
		Nonce:         nonce,
		Amount:        amount,
		From:          caller,
		To:            params.To,
		Asset:         "eth",
		UnsignedTxHex: hex.EncodeToString(unsigned),
		BlockHeight:   blocklist.GetLastHeight(),
	})
	SetPendingNonce(nonce + 1)

	return hex.EncodeToString(unsigned), nil
}

func HandleUnmapERC20(params *TransferParams, vaultAddress [20]byte, chainId uint64) (string, error) {
	if isPaused() {
		return "", ce.NewContractError(ce.ErrIntent, "contract is paused")
	}
	if HasPendingWithdrawal() {
		return "", ce.NewContractError(ce.ErrIntent, "withdrawal pending: wait for confirmation")
	}

	env := sdk.GetEnv()
	caller := env.Caller.String()

	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil || amount <= 0 {
		return "", ce.NewContractError(ce.ErrInput, "invalid amount")
	}
	if params.TokenAddress == "" {
		return "", ce.NewContractError(ce.ErrInput, "token_address required for ERC-20 withdrawal")
	}
	tokenAddr, err := crypto.HexToAddress(params.TokenAddress)
	if err != nil {
		return "", ce.Prepend(err, "token_address")
	}
	// W4 Cluster B CRIT #6 Site 10: token registry keyed by (chainId, addr).
	tokenInfo := getTokenInfo(chainId, tokenAddr)
	if tokenInfo == nil {
		return "", ErrInvalidToken
	}
	if amount < tokenInfo.MinWithdrawal {
		return "", ce.NewContractError(ce.ErrIntent, "below minimum withdrawal for this token")
	}

	recipientAddr, err := crypto.HexToAddress(params.To)
	if err != nil {
		return "", ce.Prepend(err, "recipient address")
	}
	// review2 #44: refuse the zero address (TSS-signed burn).
	if recipientAddr == ([20]byte{}) {
		return "", ce.NewContractError(ce.ErrInput, "refusing withdrawal to zero address")
	}

	header := blocklist.GetHeader(blocklist.GetLastHeight())
	if header == nil {
		return "", ce.NewContractError(ce.ErrInitialization, "no block headers available")
	}

	gasReserve := getGasReserve()
	if gasReserve < constants.MinGasReserve {
		return "", ce.NewContractError(ce.ErrBalance, "insufficient gas reserve for ERC-20 withdrawal")
	}

	gasTipCap := uint64(2_000_000_000)
	// review2 HIGH #16: checked arithmetic (see safeGasFee).
	gasFeeCap, gasCost, feeErr := safeGasFee(constants.ERC20TransferGas, header.BaseFeePerGas, 2, gasTipCap)
	if feeErr != nil {
		return "", ce.NewContractError(ce.ErrArithmetic, "gas fee computation overflow")
	}

	nonce := GetPendingNonce()
	amountBig := new(big.Int).SetInt64(amount)
	unsigned := BuildERC20WithdrawalTx(chainId, nonce, gasTipCap, gasFeeCap, tokenAddr, recipientAddr, amountBig)
	sighash := ComputeSighash(unsigned)

	if err := requireTssKey(); err != nil {
		return "", err
	}
	sdk.TssSignKey("primary", sighash)

	if !DecBalance(caller, tokenInfo.Symbol, amount) {
		return "", ce.NewContractError(ce.ErrBalance, "insufficient token balance")
	}
	TrackWithdrawal(tokenInfo.Symbol, amount)

	// W4-A Step 3b: gas reserve is gwei; convert the wei gas cost before deducting.
	deductGasReserve(gasCost / 1_000_000_000)

	StorePendingSpend(PendingSpend{
		Nonce:         nonce,
		Amount:        amount,
		From:          caller,
		To:            params.To,
		Asset:         tokenInfo.Symbol,
		TokenAddress:  params.TokenAddress,
		UnsignedTxHex: hex.EncodeToString(unsigned),
		BlockHeight:   blocklist.GetLastHeight(),
	})
	SetPendingNonce(nonce + 1)

	return hex.EncodeToString(unsigned), nil
}

func HandleConfirmSpend(req *ConfirmSpendRequest, vaultAddress [20]byte, chainId uint64) error {
	if isPaused() {
		return ce.NewContractError(ce.ErrIntent, "contract is paused")
	}

	confirmedNonce := GetConfirmedNonce()
	ps := GetPendingSpend(confirmedNonce)
	if ps == nil {
		return ce.NewContractError(ce.ErrIntent, "no pending spend at confirmed nonce")
	}

	if req.BlockHeight <= ps.BlockHeight {
		return ce.NewContractError(ce.ErrIntent, "confirmation block must be after withdrawal block")
	}

	header := blocklist.GetHeader(req.BlockHeight)
	if header == nil {
		return ErrBlockNotFound
	}

	// --- Transaction proof: verify the tx matches the pending spend ---
	txBytes, err := hex.DecodeString(req.TxHex)
	if err != nil {
		return ce.WrapContractError(ce.ErrInvalidHex, err, "tx_hex")
	}
	txProofBytes, err := hex.DecodeString(req.TxProofHex)
	if err != nil {
		return ce.WrapContractError(ce.ErrInvalidHex, err, "tx_proof_hex")
	}

	txProof := splitProofNodes(txProofBytes)
	txKey := rlp.EncodeUint64(req.TxIndex)
	provenTx, err := mpt.VerifyProof(header.TransactionsRoot, txKey, txProof)
	if err != nil {
		return ce.Prepend(err, "tx proof")
	}
	if !bytesEqual(provenTx, txBytes) {
		return ce.NewContractError(ce.ErrTransaction, "tx does not match proof")
	}

	parsedTx, err := parseTransaction(txBytes)
	if err != nil {
		return ce.Prepend(err, "parse proven tx")
	}
	if parsedTx.Nonce != ps.Nonce {
		return ce.NewContractError(ce.ErrTransaction, "tx nonce does not match pending spend")
	}
	if parsedTx.ChainId != chainId {
		return ce.NewContractError(ce.ErrTransaction, "tx chain id does not match contract chain id")
	}

	// CRIT #11 site 6 (SYSTEM, REJECT): vault TSS-sig recovery. Post
	// CRIT #24, TSS-lib always produces low-S signatures, so high-S here
	// signals tampering or replay-with-malleated-sig. Use EcrecoverStrict
	// so any non-canonical sig is rejected rather than normalized through.
	sighash := computeTxSighash(txBytes, parsedTx)
	recoveredSender, err := crypto.EcrecoverStrict(sighash, 27+parsedTx.V, padTo32(parsedTx.R), padTo32(parsedTx.S))
	if err != nil {
		return ce.Prepend(err, "ecrecover")
	}
	if recoveredSender == ([20]byte{}) {
		return ce.NewContractError(ce.ErrTransaction, "ecrecover returned zero address")
	}
	if recoveredSender != vaultAddress {
		return ce.NewContractError(ce.ErrTransaction, "tx not signed by vault")
	}

	psTo, err := crypto.HexToAddress(ps.To)
	if err != nil {
		return ce.Prepend(err, "pending spend destination")
	}
	if ps.Asset == "eth" {
		if parsedTx.To != psTo {
			return ce.NewContractError(ce.ErrTransaction, "tx destination does not match pending spend")
		}
		// W4-A Step 3b: tx value is wei; ps.Amount is gwei. Convert with the
		// same Div as VerifyETHDeposit so the truncation invariant holds.
		txAmountWei := new(big.Int).SetBytes(parsedTx.Value)
		txAmountGwei := new(big.Int).Div(txAmountWei, WeiPerGwei)
		if !txAmountGwei.IsInt64() || txAmountGwei.Int64() != ps.Amount {
			return ce.NewContractError(ce.ErrTransaction, "tx amount does not match pending spend")
		}
	} else {
		// ERC-20: tx.to is the token contract, value is 0, calldata is transfer(recipient, amount).
		tokenAddr, err := crypto.HexToAddress(ps.TokenAddress)
		if err != nil {
			return ce.Prepend(err, "pending spend token address")
		}
		if parsedTx.To != tokenAddr {
			return ce.NewContractError(ce.ErrTransaction, "tx token contract does not match pending spend")
		}
		if new(big.Int).SetBytes(parsedTx.Value).Sign() != 0 {
			return ce.NewContractError(ce.ErrTransaction, "erc20 tx must have zero value")
		}
		if len(parsedTx.Data) != 68 {
			return ce.NewContractError(ce.ErrTransaction, "erc20 calldata must be 68 bytes")
		}
		if !bytesEqual(parsedTx.Data[0:4], abi.TransferSelector) {
			return ce.NewContractError(ce.ErrTransaction, "erc20 calldata selector mismatch")
		}
		// First 12 bytes of address slot must be zero (left-padded address).
		for _, b := range parsedTx.Data[4:16] {
			if b != 0 {
				return ce.NewContractError(ce.ErrTransaction, "erc20 recipient padding non-zero")
			}
		}
		if !bytesEqual(parsedTx.Data[16:36], psTo[:]) {
			return ce.NewContractError(ce.ErrTransaction, "erc20 recipient does not match pending spend")
		}
		callAmount := new(big.Int).SetBytes(parsedTx.Data[36:68])
		if !callAmount.IsInt64() || callAmount.Int64() != ps.Amount {
			return ce.NewContractError(ce.ErrTransaction, "erc20 amount does not match pending spend")
		}
	}

	// --- Receipt proof: determine success or failure ---
	receiptBytes, err := hex.DecodeString(req.ReceiptHex)
	if err != nil {
		return ce.WrapContractError(ce.ErrInvalidHex, err, "receipt_hex")
	}
	receiptProofBytes, err := hex.DecodeString(req.ReceiptProofHex)
	if err != nil {
		return ce.WrapContractError(ce.ErrInvalidHex, err, "receipt_proof_hex")
	}

	receiptProof := splitProofNodes(receiptProofBytes)
	receiptKey := rlp.EncodeUint64(req.TxIndex)
	provenReceipt, err := mpt.VerifyProof(header.ReceiptsRoot, receiptKey, receiptProof)
	if err != nil {
		return ce.Prepend(err, "receipt proof")
	}
	if !bytesEqual(provenReceipt, receiptBytes) {
		return ce.NewContractError(ce.ErrTransaction, "receipt does not match proof")
	}

	receiptToParse := receiptBytes
	if len(receiptToParse) > 0 && receiptToParse[0] <= 0x7f {
		receiptToParse = receiptToParse[1:]
	}
	items, err := rlp.DecodeList(receiptToParse)
	if err != nil || len(items) < 1 {
		return ce.NewContractError(ce.ErrInput, "invalid receipt RLP")
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
		return ce.NewContractError(ce.ErrIntent, "contract is paused")
	}
	env := sdk.GetEnv()
	caller := env.Caller.String()

	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil || amount <= 0 {
		return ce.NewContractError(ce.ErrInput, "invalid amount")
	}

	// review2 #43: an empty recipient credited the "" address, making the
	// funds permanently unspendable. Reject it.
	if params.To == "" {
		return ce.NewContractError(ce.ErrInput, "invalid recipient")
	}

	if !DecBalance(caller, params.Asset, amount) {
		return ce.NewContractError(ce.ErrBalance, "insufficient balance")
	}
	if err := IncBalance(params.To, params.Asset, amount); err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "recipient balance overflow")
	}
	return nil
}

func HandleTransferFrom(params *TransferParams) error {
	if isPaused() {
		return ce.NewContractError(ce.ErrIntent, "contract is paused")
	}
	env := sdk.GetEnv()
	caller := env.Caller.String()

	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil || amount <= 0 {
		return ce.NewContractError(ce.ErrInput, "invalid amount")
	}

	// review2 #43: reject empty recipient (funds would be unspendable).
	if params.To == "" {
		return ce.NewContractError(ce.ErrInput, "invalid recipient")
	}

	allowance := GetAllowance(params.From, caller, params.Asset)
	if allowance < amount {
		return ce.NewContractError(ce.ErrBalance, "insufficient allowance")
	}

	if !DecBalance(params.From, params.Asset, amount) {
		return ce.NewContractError(ce.ErrBalance, "insufficient balance")
	}
	SetAllowance(params.From, caller, params.Asset, allowance-amount)
	if err := IncBalance(params.To, params.Asset, amount); err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "recipient balance overflow")
	}
	return nil
}

func HandleApprove(params *AllowanceParams) error {
	if isPaused() {
		return ce.NewContractError(ce.ErrIntent, "contract is paused")
	}
	env := sdk.GetEnv()
	caller := env.Caller.String()

	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil || amount < 0 {
		return ce.NewContractError(ce.ErrInput, "invalid amount")
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
	key := constants.TokenRegistryPrefix + strconv.FormatUint(
		chainId,
		10,
	) + constants.DirPathDelimiter + hex.EncodeToString(
		addr[:],
	)
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
	key := constants.TokenRegistryPrefix + strconv.FormatUint(
		chainId,
		10,
	) + constants.DirPathDelimiter + hex.EncodeToString(
		addr[:],
	)
	sdk.StateSetObject(
		key,
		symbol+"|"+strconv.FormatUint(uint64(decimals), 10)+"|"+strconv.FormatInt(minWithdrawal, 10),
	)
}

func requireTssKey() error {
	keyInfo := sdk.TssGetKey("primary")
	if keyInfo == "" || keyInfo == "fail" {
		return ce.NewContractError(ce.ErrAuth, "TSS key not available")
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
		return ce.NewContractError(ce.ErrIntent, "contract is paused")
	}
	if HasPendingWithdrawal() {
		return ce.NewContractError(ce.ErrIntent, "withdrawal pending: wait for confirmation")
	}

	env := sdk.GetEnv()
	caller := env.Caller.String()

	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil || amount <= 0 {
		return ce.NewContractError(ce.ErrInput, "invalid amount")
	}
	if params.Asset == "eth" && amount < constants.MinETHWithdrawal {
		return ce.NewContractError(ce.ErrIntent, "below minimum ETH withdrawal")
	}

	if err := requireTssKey(); err != nil {
		return err
	}

	// Validate ALL inputs BEFORE any state mutations
	toAddr, err := crypto.HexToAddress(params.To)
	if err != nil {
		return ce.Prepend(err, "destination address")
	}
	// review2 #44: refuse the zero address (TSS-signed burn).
	if toAddr == ([20]byte{}) {
		return ce.NewContractError(ce.ErrInput, "refusing withdrawal to zero address")
	}

	header := blocklist.GetHeader(blocklist.GetLastHeight())
	if header == nil {
		return ce.NewContractError(ce.ErrInitialization, "no block headers available")
	}

	// W4 Cluster C CRIT #7: compute gas pricing up front for BOTH paths so
	// the reserve floor check applies to ETH-path withdrawals (pre-fix the
	// floor check was only run on the ERC-20 path; the ETH path skipped it
	// entirely, drained the vault, and never deducted fees from the owner).
	gasTipCap := uint64(2_000_000_000)
	// review2 HIGH #16: checked cap (gasUnits=0 → just the gasFeeCap; the
	// per-path fees are computed with safeGasFee below). An extreme base fee
	// can't wrap uint64 into a tiny gasFeeCap and sign an under-priced tx.
	gasFeeCap, _, capErr := safeGasFee(0, header.BaseFeePerGas, 2, gasTipCap)
	if capErr != nil {
		return ce.NewContractError(ce.ErrArithmetic, "gas fee computation overflow")
	}

	var tokenAddr [20]byte
	if params.Asset != "eth" {
		if params.TokenAddress == "" {
			return ce.NewContractError(ce.ErrInput, "token_address required")
		}
		tokenAddr, err = crypto.HexToAddress(params.TokenAddress)
		if err != nil {
			return ce.Prepend(err, "token_address")
		}
		// W4 Cluster B CRIT #6 Site 10: token registry keyed by (chainId, addr).
		tokenInfo := getTokenInfo(chainId, tokenAddr)
		if tokenInfo == nil {
			return ErrInvalidToken
		}
		if amount < tokenInfo.MinWithdrawal {
			return ce.NewContractError(ce.ErrIntent, "below minimum withdrawal for this token")
		}
		if getGasReserve() < constants.MinGasReserve {
			return ce.NewContractError(ce.ErrBalance, "insufficient gas reserve for ERC-20 withdrawal")
		}
	} else {
		// W4 Cluster C CRIT #7: ETH path now also enforces the gas reserve
		// floor + debits (amount + fee) from the owner.
		if getGasReserve() < constants.MinGasReserve {
			return ce.NewContractError(ce.ErrTransaction, "insufficient gas reserve")
		}
	}

	allowance := GetAllowance(params.From, caller, params.Asset)
	if allowance < amount {
		return ce.NewContractError(ce.ErrBalance, "insufficient allowance")
	}

	// W4 Cluster C CRIT #7 (ETH path) — compute the gas fee and debit
	// (amount + fee) instead of just amount. Pre-fix, the ETH path
	// computed no fee and the vault absorbed the L1 mining cost on every
	// withdrawal. Route the addition through SafeAdd64 (W2 CRIT #3).
	totalDeduct := amount
	if params.Asset == "eth" {
		_, feeWei, feeErr := safeGasFee(constants.ETHTransferGas, header.BaseFeePerGas, 2, gasTipCap)
		if feeErr != nil {
			return ce.NewContractError(ce.ErrArithmetic, "gas fee computation overflow")
		}
		if params.MaxFee != "" {
			maxFee, perr := strconv.ParseInt(params.MaxFee, 10, 64)
			if perr != nil {
				return ce.NewContractError(ce.ErrInput, "invalid max_fee")
			}
			if maxFee < 0 {
				return ce.NewContractError(ce.ErrInput, "max_fee must be non-negative")
			}
			if feeWei > maxFee {
				return ce.NewContractError(ce.ErrTransaction, "fee exceeds max_fee")
			}
		}
		// Step 3b: gwei conversion before SafeAdd64.
		fee := feeWei / 1_000_000_000
		td, addErr := SafeAdd64(amount, fee)
		if addErr != nil {
			return ce.NewContractError(ce.ErrArithmetic, "amount+fee overflow")
		}
		totalDeduct = td
		if params.DeductFee {
			totalDeduct = amount
		}
		if GetBalance(params.From, "eth") < totalDeduct {
			return ce.NewContractError(ce.ErrTransaction, "insufficient balance in owner account")
		}
	}

	// All validation passed — now mutate state
	if !DecBalance(params.From, params.Asset, totalDeduct) {
		return ce.NewContractError(ce.ErrBalance, "insufficient balance in owner account")
	}
	SetAllowance(params.From, caller, params.Asset, allowance-amount)
	TrackWithdrawal(params.Asset, amount)

	nonce := GetPendingNonce()

	var unsigned []byte
	var asset string
	var tokenAddress string
	if params.Asset == "eth" {
		// W4-A Step 3b: ETH amount is gwei; scale to wei for the L1 tx.
		amountBig := new(big.Int).Mul(big.NewInt(amount), WeiPerGwei)
		unsigned = BuildETHWithdrawalTx(chainId, nonce, gasTipCap, gasFeeCap, toAddr, amountBig)
		asset = "eth"
	} else {
		// ERC-20: token-native units (no gwei scaling).
		amountBig := new(big.Int).SetInt64(amount)
		unsigned = BuildERC20WithdrawalTx(chainId, nonce, gasTipCap, gasFeeCap, tokenAddr, toAddr, amountBig)
		asset = params.Asset
		tokenAddress = params.TokenAddress
		// review2 HIGH #16: checked gas cost (wei); Step 3b converts to gwei
		// for the gwei-denominated reserve.
		_, gasReserveFee, feeErr := safeGasFee(constants.ERC20TransferGas, header.BaseFeePerGas, 2, gasTipCap)
		if feeErr != nil {
			return ce.NewContractError(ce.ErrArithmetic, "gas fee computation overflow")
		}
		deductGasReserve(gasReserveFee / 1_000_000_000)
	}

	sighash := ComputeSighash(unsigned)
	sdk.TssSignKey("primary", sighash)

	StorePendingSpend(PendingSpend{
		Nonce:         nonce,
		Amount:        amount,
		From:          params.From,
		To:            params.To,
		Asset:         asset,
		TokenAddress:  tokenAddress,
		UnsignedTxHex: hex.EncodeToString(unsigned),
		BlockHeight:   blocklist.GetLastHeight(),
	})
	SetPendingNonce(nonce + 1)
	return nil
}

func HandleIncreaseAllowance(params *AllowanceParams) error {
	if isPaused() {
		return ce.NewContractError(ce.ErrIntent, "contract is paused")
	}
	env := sdk.GetEnv()
	caller := env.Caller.String()

	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil || amount <= 0 {
		return ce.NewContractError(ce.ErrInput, "invalid amount")
	}

	current := GetAllowance(caller, params.Spender, params.Asset)
	newVal, err := SafeAdd64(current, amount)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "allowance overflow")
	}
	SetAllowance(caller, params.Spender, params.Asset, newVal)
	return nil
}

func HandleDecreaseAllowance(params *AllowanceParams) error {
	if isPaused() {
		return ce.NewContractError(ce.ErrIntent, "contract is paused")
	}
	env := sdk.GetEnv()
	caller := env.Caller.String()

	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil || amount <= 0 {
		return ce.NewContractError(ce.ErrInput, "invalid amount")
	}

	current := GetAllowance(caller, params.Spender, params.Asset)
	newVal := current - amount
	if newVal < 0 {
		newVal = 0
	}
	SetAllowance(caller, params.Spender, params.Asset, newVal)
	return nil
}

func HandleReplaceWithdrawal(vaultAddress [20]byte, chainId uint64) {
	confirmedNonce := GetConfirmedNonce()
	ps := GetPendingSpend(confirmedNonce)
	if ps == nil {
		ce.Abort(ce.ErrIntent, "no pending withdrawal to replace", "replaceWithdrawal")
		return
	}

	// Rebuild with 2x gas
	header := blocklist.GetHeader(blocklist.GetLastHeight())
	if header == nil {
		ce.Abort(ce.ErrInitialization, "no headers", "replaceWithdrawal")
		return
	}

	gasTipCap := uint64(4_000_000_000) // doubled
	// review2 HIGH #16: replaceWithdrawal re-prices at 3x base fee. Route the
	// cap through the checked helper so an extreme base fee can't wrap uint64
	// into a tiny gasFeeCap and sign an under-priced replacement. gasUnits=0:
	// no fee is charged here — the reserve was deducted at the original unmap.
	gasFeeCap, _, feeErr := safeGasFee(0, header.BaseFeePerGas, 3, gasTipCap)
	if feeErr != nil {
		ce.Abort(ce.ErrArithmetic, "gas fee cap overflow", "replaceWithdrawal")
		return
	}

	toAddr, _ := crypto.HexToAddress(ps.To)

	var unsigned []byte
	if ps.Asset == "eth" {
		// W4-A Step 3b: ps.Amount is gwei; scale to wei for the L1 tx.
		amountBig := new(big.Int).Mul(big.NewInt(ps.Amount), WeiPerGwei)
		unsigned = BuildETHWithdrawalTx(chainId, confirmedNonce, gasTipCap, gasFeeCap, toAddr, amountBig)
	} else {
		amountBig := new(big.Int).SetInt64(ps.Amount)
		tokenAddr, _ := crypto.HexToAddress(ps.TokenAddress)
		unsigned = BuildERC20WithdrawalTx(chainId, confirmedNonce, gasTipCap, gasFeeCap, tokenAddr, toAddr, amountBig)
	}

	sighash := ComputeSighash(unsigned)
	sdk.TssSignKey("primary", sighash)

	// Update pending spend with new signed TX
	ps.UnsignedTxHex = hex.EncodeToString(unsigned)
	StorePendingSpend(*ps)
}

func HandleClearNonce(vaultAddress [20]byte, chainId uint64) {
	confirmedNonce := GetConfirmedNonce()
	ps := GetPendingSpend(confirmedNonce)
	if ps == nil {
		ce.Abort(ce.ErrIntent, "no pending nonce to clear", "clearNonce")
		return
	}

	// Build 0-value self-transfer to advance nonce
	unsigned := BuildETHWithdrawalTx(
		chainId,
		confirmedNonce,
		4_000_000_000,
		100_000_000_000,
		vaultAddress,
		big.NewInt(0),
	)
	sighash := ComputeSighash(unsigned)
	sdk.TssSignKey("primary", sighash)

	// Best-effort refund: if the user's balance is at the int64 ceiling we cannot
	// credit them, but the contract MUST still advance the nonce or it will jam.
	// Only update supply when the refund actually landed, otherwise balance and
	// supply diverge.
	if err := IncBalance(ps.From, ps.Asset, ps.Amount); err == nil {
		sup := GetSupply(ps.Asset)
		sup.Active += ps.Amount
		sup.User += ps.Amount
		SetSupply(ps.Asset, sup)
	}
	DeletePendingSpend(confirmedNonce)
	SetConfirmedNonce(confirmedNonce + 1)
	SetPendingNonce(confirmedNonce + 1)
}
