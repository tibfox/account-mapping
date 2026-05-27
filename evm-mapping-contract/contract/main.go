package main

// EVM Mapping Contract — Magi/VSC
// - must import sdk or build fails

import (
	"encoding/json"
	"evm-mapping-contract/contract/admin"
	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/mapping"
	"evm-mapping-contract/sdk"
	"strconv"
)

var NetworkMode string

func main() {}

func vault() [20]byte {
	data := sdk.StateGetObject(constants.VaultAddressKey)
	if data == nil {
		return [20]byte{}
	}
	addr, _ := crypto.HexToAddress(*data)
	return addr
}

func chainId() uint64 {
	data := sdk.StateGetObject(constants.ChainIdKey)
	if data == nil {
		return 1
	}
	v, _ := strconv.ParseUint(*data, 10, 64)
	return v
}

// checkAdmin / checkOwner — W4 Cluster C v20 §BD SERIOUS-3:
// these two functions MUST remain separate.
//   - checkOwner is called from the propose/execute dispatcher; it gates
//     every admin transition by checking caller == contract.owner. The
//     Hive L1 2-of-3 multisig is enforced BEFORE the call reaches the
//     contract (D-C-1 + D-C-2). Per v10 user correction, contract code
//     does NOT do contract-internal N-of-M counting.
//   - checkAdmin is the legacy name kept for compile compatibility with
//     prior wave touch-points; it is now identical to checkOwner. It is
//     NOT redirected to read oracle_account — doing so would let the
//     oracle relay account execute Operator-tactical proposals
//     (replaceBlock / replaceWithdrawal / clearNonce), a privilege
//     escalation explicitly called out in W1 §D-C-8 SERIOUS-3.
func checkAdmin() {
	checkOwner()
}

func checkOwner() {
	caller := sdk.GetEnv().Caller.String()
	owner := sdk.GetEnvKey("contract.owner")
	if owner == nil || caller != *owner {
		ce.CustomAbort(ce.NewContractError(ce.ErrNoPermission, "owner required"))
	}
}

// checkOracleAccount — W4 Cluster C v20 §BD (SERIOUS-3): dedicated gate for
// `addBlocks` ONLY. Reads the `oracle_account` state key populated by the
// setOracleAccount admin handler (which itself goes through propose/execute
// at the 7.2K-block Operational class). Owner is ALSO accepted so the
// pre-setOracleAccount state (where the key is empty) does not deadlock
// the oracle feed on a fresh-deploy contract — initContract sets
// oracle_account = deployer at deploy time, but the owner-fallback also
// covers a missed initContract.
func checkOracleAccount() {
	caller := sdk.GetEnv().Caller.String()
	owner := sdk.GetEnvKey("contract.owner")
	if owner != nil && caller == *owner {
		return
	}
	oracleAcc := sdk.StateGetObject(constants.OracleAccountKey)
	if oracleAcc == nil || *oracleAcc == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrNoPermission, "addBlocks: oracle account not configured"))
	}
	if caller != *oracleAcc {
		ce.CustomAbort(ce.NewContractError(ce.ErrNoPermission, "addBlocks: oracle account required"))
	}
}

// assertNotPaused — wraps the dispatchAdmin business logic for every gate
// touched by the propose/execute migration per W1 §D-C-9. Exceptions:
//   - pause   — must always be callable (no assertNotPaused)
//   - unpause — must always be callable (no assertNotPaused)
//   - init    — deploy-time only
//   - addBlocks — EXEMPT from propose/execute (v20 §BD)
func assertNotPaused() {
	if err := mapping.AssertNotPaused(); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
}

// -----------------------------------------------------------------------------
// initContract — W4 Cluster C v21 SERIOUS-2 + NOTABLE-1:
// deploy-time idempotent setup. Sets oracle_account = caller (the
// deployer / contract owner) and optionally seeds the is_testnet sentinel
// for cross-contract namespace isolation (Cluster E's clearTestnetState
// reads is_testnet).
//
// Re-entry guard: subsequent invocations fail because constants.InitMarkerKey
// is set on first successful call. This matches Cluster B's zk-header-verifier
// initContract pattern (§BF).
// -----------------------------------------------------------------------------

type initContractParams struct {
	IsTestnet bool `json:"is_testnet"`
}

//go:wasmexport initContract
func initContract(input *string) *string {
	if existing := sdk.StateGetObject(constants.InitMarkerKey); existing != nil && *existing == "1" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInitialization, "contract already initialized"))
	}
	caller := sdk.GetEnv().Caller.String()
	owner := sdk.GetEnvKey("contract.owner")
	if owner == nil || caller != *owner {
		ce.CustomAbort(ce.NewContractError(ce.ErrNoPermission, "initContract requires deployer"))
	}
	// Default values; input may be nil/empty.
	var params initContractParams
	if input != nil && *input != "" {
		_ = json.Unmarshal([]byte(*input), &params)
	}
	// Seed the oracle account to the deployer so the first oracle-relay
	// addBlocks call goes through; operator can then setOracleAccount via
	// the propose/execute flow (7.2K timelock) to swap it to the dedicated
	// oracle account when ready.
	sdk.StateSetObject(constants.OracleAccountKey, caller)
	if params.IsTestnet {
		sdk.StateSetObject("is_testnet", "true")
	}
	sdk.StateSetObject(constants.InitMarkerKey, "1")
	return nil
}

// -----------------------------------------------------------------------------
// User-facing wasmexports (NOT admin — no propose/execute wrapping)
// -----------------------------------------------------------------------------

//go:wasmexport map
func mapDeposit(input *string) *string {
	var params mapping.MapParams
	json.Unmarshal([]byte(*input), &params)
	// W4 Cluster C CRIT #8: HandleMap performs the relayer-whitelist
	// check for the native ETH path (mapping/handlers.go) — the wasmexport
	// itself stays permissionless so the gate is enforced once, where it
	// can also see the deposit type.
	if err := mapping.HandleMap(&params, vault(), chainId()); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport unmapETH
func unmapETH(input *string) *string {
	var params mapping.TransferParams
	json.Unmarshal([]byte(*input), &params)
	if _, err := mapping.HandleUnmapETH(&params, vault(), chainId()); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport unmapERC20
func unmapERC20(input *string) *string {
	var params mapping.TransferParams
	json.Unmarshal([]byte(*input), &params)
	if _, err := mapping.HandleUnmapERC20(&params, vault(), chainId()); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport confirmSpend
func confirmSpend(input *string) *string {
	var req mapping.ConfirmSpendRequest
	json.Unmarshal([]byte(*input), &req)
	// W4 Cluster F: HandleConfirmSpend signature has NO vaultAddress
	// parameter — it reads ps.VaultAtQueue from the stored PendingSpend.
	if err := mapping.HandleConfirmSpend(&req, chainId()); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport transfer
func transfer(input *string) *string {
	var params mapping.TransferParams
	json.Unmarshal([]byte(*input), &params)
	if err := mapping.HandleTransfer(&params); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport transferFrom
func transferFrom(input *string) *string {
	var params mapping.TransferParams
	json.Unmarshal([]byte(*input), &params)
	if err := mapping.HandleTransferFrom(&params); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport approve
func approve(input *string) *string {
	var params mapping.AllowanceParams
	json.Unmarshal([]byte(*input), &params)
	if err := mapping.HandleApprove(&params); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport unmapFrom
func unmapFrom(input *string) *string {
	var params mapping.TransferParams
	json.Unmarshal([]byte(*input), &params)
	if err := mapping.HandleUnmapFrom(&params, vault(), chainId()); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport increaseAllowance
func increaseAllowance(input *string) *string {
	var params mapping.AllowanceParams
	json.Unmarshal([]byte(*input), &params)
	if err := mapping.HandleIncreaseAllowance(&params); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport decreaseAllowance
func decreaseAllowance(input *string) *string {
	var params mapping.AllowanceParams
	json.Unmarshal([]byte(*input), &params)
	if err := mapping.HandleDecreaseAllowance(&params); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport getInfo
func getInfo(_ *string) *string { return nil }

// -----------------------------------------------------------------------------
// addBlocks — EXEMPT from propose/execute per W1 §D-C-8 (v20 §BD).
// The oracle relay submits one of these per ETH block tick; wrapping each
// in a 6h timelock would halt the oracle feed. Instead, the oracle account
// identity is what is timelocked (via setOracleAccount, which DOES go
// through propose/execute at the Operational class).
// -----------------------------------------------------------------------------

//go:wasmexport addBlocks
func addBlocks(input *string) *string {
	checkOracleAccount()
	var params blocklist.AddBlocksParams
	json.Unmarshal([]byte(*input), &params)
	if err := blocklist.HandleAddBlocks(&params, chainId()); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

// -----------------------------------------------------------------------------
// W4 Cluster C — propose / execute / cancel / expireProposal wasmexports.
//
// Per W1 §D-C-1 (LOCKED): contract checks caller == owner; Hive L1 enforces
// the 2-of-3 weighted multisig BEFORE the call reaches the contract.
//
// Per W1 §D-C-6 (LOCKED): execute(proposalId) takes ONLY the id; payload is
// read from stored proposal so no re-supply is possible. payloadHash is
// re-verified inside admin.ExecuteValidated.
//
// Per W1 §D-C-7 (LOCKED): every state transition emits an event with the
// {action, actor, proposalId, payloadHash, queueHeight, execHeight, status}
// shape. admin/proposals.go's emit() owns the JSON marshaling.
// -----------------------------------------------------------------------------

//go:wasmexport propose
func propose(input *string) *string {
	checkOwner()
	var req admin.ProposeRequest
	if input != nil {
		json.Unmarshal([]byte(*input), &req)
	}
	payload, err := admin.DecodePayloadHex(req.PayloadHex)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInvalidHex, "payload_hex invalid"))
	}
	env := sdk.GetEnv()
	id, perr := admin.Propose(req.Action, payload, env.Caller.String(), env.BlockHeight)
	if perr != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, perr.Error()))
	}
	resp := admin.ProposeResponse{ProposalId: id, ExecHeight: 0}
	// fetch the just-stored proposal so the caller learns the exec_height.
	if pp := admin.LoadProposal(id); pp != nil {
		resp.ExecHeight = pp.ExecHeight
	}
	out, _ := json.Marshal(resp)
	s := string(out)
	return &s
}

//go:wasmexport execute
func execute(input *string) *string {
	checkOwner()
	var req admin.IdRequest
	if input != nil {
		json.Unmarshal([]byte(*input), &req)
	}
	env := sdk.GetEnv()
	pp, err := admin.ExecuteValidated(req.ProposalId, env.BlockHeight, env.Caller.String())
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	dispatchAdmin(pp.Action, pp.Payload)
	return nil
}

//go:wasmexport cancel
func cancel(input *string) *string {
	checkOwner()
	var req admin.IdRequest
	if input != nil {
		json.Unmarshal([]byte(*input), &req)
	}
	env := sdk.GetEnv()
	if err := admin.Cancel(req.ProposalId, env.Caller.String()); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

// expireProposal — NOT named expireWithdrawal (that name belongs to
// Cluster E's withdrawal-lifecycle handler; both wasmexports must land
// in the same atomic WASM binary). Permissionless after expireHeight.
//go:wasmexport expireProposal
func expireProposal(input *string) *string {
	var req admin.IdRequest
	if input != nil {
		json.Unmarshal([]byte(*input), &req)
	}
	env := sdk.GetEnv()
	if err := admin.ExpireProposal(req.ProposalId, env.BlockHeight, env.Caller.String()); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

// -----------------------------------------------------------------------------
// W4 Cluster E withdrawal-lifecycle wasmexports.
//
// expireWithdrawal — CRIT #26 (D-E-3 LOCKED). Permissionless after
//   ps.BlockHeight + WithdrawalExpiryWindow (5000 Hive blocks ≈ 4h). The
//   original withdrawer can call BEFORE the window for convenience
//   (early-cancel) but MUST supply an L1ProofOfDrop. Post-window callers
//   MAY supply a proof (opportunistic verify); if absent, the handler
//   allows expiry on the timeout alone (TSS-stuck withdrawals path).
//
// cancelMyWithdrawal — CRIT #26 companion. Only ps.From can call.
//   Proof MANDATORY (must NOT race in-flight L1 tx). TSS-signs a self-
//   transfer to roll the L1 vault nonce.
//
// Both names DISTINCT from Cluster C's expireProposal (W4 PROGRESS-LOG
// downstream pin: "different wasmexport names").
// -----------------------------------------------------------------------------

//go:wasmexport expireWithdrawal
func expireWithdrawal(input *string) *string {
	if input == nil || *input == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "expireWithdrawal: empty payload"))
	}
	var params mapping.ExpireWithdrawalParams
	if err := json.Unmarshal([]byte(*input), &params); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "expireWithdrawal: bad payload"))
	}
	if err := mapping.HandleExpireWithdrawal(params.Nonce, params.Proof); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport cancelMyWithdrawal
func cancelMyWithdrawal(input *string) *string {
	if input == nil || *input == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "cancelMyWithdrawal: empty payload"))
	}
	var params mapping.CancelMyWithdrawalParams
	if err := json.Unmarshal([]byte(*input), &params); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "cancelMyWithdrawal: bad payload"))
	}
	if err := mapping.HandleCancelMyWithdrawal(params.Nonce, params.Proof, vault(), chainId()); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

// confirmSpendSchema — W4 Cluster E CRIT #5 (D-E-1). Returns the canonical
// ConfirmSpendRequest schema JSON as a string so the bot can introspect at
// startup and verify its hard-coded schema fingerprint matches. Per D-E-1
// backward-compat note: if the bot connects to a contract WITHOUT this
// export (older testnet redeploy), it should fall back to the hard-coded
// schema and log a warning — the export is OPTIONAL but the schema is not.
//
//go:wasmexport confirmSpendSchema
func confirmSpendSchema(_ *string) *string {
	s := mapping.ConfirmSpendSchemaJSON
	return &s
}

// -----------------------------------------------------------------------------
// dispatchAdmin — invoked from execute() AFTER the timelock has elapsed and
// the proposal payloadHash has been re-verified. Each case decodes its
// action's input struct from JSON (per W1 §D-C-5 — payload IS the canonical
// JSON of the existing handler input struct) and runs the inner handler.
//
// assertNotPaused() per W1 §D-C-9: applied to EVERY case except pause /
// unpause / initContract. createKey / renewKey / clearNonce /
// replaceWithdrawal explicitly listed (W4 Step 2 acceptance criteria —
// these previously called checkAdmin() not checkOwner(), so the gate
// MUST be set inside the dispatch case, not at the multisig-check site).
// -----------------------------------------------------------------------------

func dispatchAdmin(action string, payload []byte) {
	switch action {

	// --------------------------------------------------------------
	// Fund-affecting (Long, 400K blocks)
	// --------------------------------------------------------------
	case "setVault":
		assertNotPaused()
		// Payload is the raw 0x-prefixed vault address string per the
		// pre-fix wasmexport contract (json.Marshal of the input *string).
		// Accept either a JSON string ("0x...") or a plain hex address.
		addr, perr := decodeAddressPayload(payload)
		if perr != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "setVault: "+perr.Error()))
		}
		sdk.StateSetObject(constants.VaultAddressKey, addr)

	case "setVerifierContract":
		assertNotPaused()
		var p struct {
			ContractId string `json:"contract_id"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "setVerifierContract: bad payload"))
		}
		sdk.StateSetObject(constants.VerifierContractIdKey, p.ContractId)

	case "createKey":
		assertNotPaused()
		sdk.TssCreateKey("primary", "ecdsa", 365)

	case "renewKey":
		assertNotPaused()
		// CRIT #17 flag 1 / W4 Cluster F D-F-1: TssRenewKey extends
		// ExpiryEpoch (NOT TssCreateKey, which would be a no-op).
		sdk.TssRenewKey("primary", 365)

	// --------------------------------------------------------------
	// Operator-tactical (28.8K blocks, 24h)
	// --------------------------------------------------------------
	case "registerPublicKey":
		assertNotPaused()
		// pre-fix wasmexport stored the raw input directly under the key.
		sdk.StateSetObject(constants.PrimaryPublicKeyKey, string(payload))

	case "replaceBlock":
		assertNotPaused()
		var entry blocklist.AddBlockEntry
		if err := json.Unmarshal(payload, &entry); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "replaceBlock: bad payload"))
		}
		// HIGH #9 / HIGH #35 observed-list invalidation lives inside
		// HandleReplaceBlock now (single state-write atomic with header
		// store).
		if err := blocklist.HandleReplaceBlock(&entry, chainId()); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
		}

	case "replaceWithdrawal":
		// W4 Cluster E CRIT #27 (D-E-5) + HIGH #26: HandleReplaceWithdrawal
		// now returns an error (was void with mid-flow sdk.Revert pre-fix).
		// Route the error through ce.CustomAbort so the L2 sees a structured
		// revert reason. assertNotPaused now lives INSIDE the handler too
		// (CRIT #27 pause-guard gap closure); we still call it here so
		// dispatchAdmin matches the §D-C-9 pattern explicitly.
		assertNotPaused()
		if err := mapping.HandleReplaceWithdrawal(vault(), chainId()); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
		}

	case "clearNonce":
		// W4 Cluster E CRIT #27 (B-E-4 + S-E-v17-2 LOCKED): signature now
		// includes an L1ProofOfDrop parameter. Pre-fix the wasmexport
		// (clearNonce) ignored its input entirely with `_ *string`, so the
		// proof field was unreachable from any L2 transaction payload —
		// validation never fired regardless of how the handler signature
		// changed. The propose/execute payload now carries a
		// ClearNonceParams JSON struct with a Proof field.
		assertNotPaused()
		var p mapping.ClearNonceParams
		if err := json.Unmarshal(payload, &p); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "clearNonce: bad payload"))
		}
		if err := mapping.HandleClearNonce(vault(), chainId(), p.Proof); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
		}

	// --------------------------------------------------------------
	// Operational (7.2K blocks, 6h)
	// --------------------------------------------------------------
	case "registerToken":
		assertNotPaused()
		var p mapping.RegisterTokenParams
		if err := json.Unmarshal(payload, &p); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "registerToken: bad payload"))
		}
		addr, herr := crypto.HexToAddress(p.Address)
		if herr != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "registerToken: invalid address"))
		}
		mapping.RegisterToken(chainId(), addr, p.Symbol, p.Decimals, p.MinWithdrawal)

	case "registerRouter":
		assertNotPaused()
		sdk.StateSetObject(constants.RouterContractIdKey, string(payload))

	case "setGasReserve":
		assertNotPaused()
		sdk.StateSetObject(constants.GasReserveKey, string(payload))

	case "seedBlocks":
		assertNotPaused()
		// Pre-fix gate: only allowed when h=0 — same condition preserved.
		if blocklist.GetLastHeight() > 0 {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "seedBlocks only allowed when h=0"))
		}
		var entry blocklist.AddBlockEntry
		if err := json.Unmarshal(payload, &entry); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "seedBlocks: bad payload"))
		}
		if err := blocklist.HandleSeedBlock(&entry, chainId()); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
		}

	case "setOracleAccount":
		assertNotPaused()
		var p struct {
			Account string `json:"account"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "setOracleAccount: bad payload"))
		}
		if p.Account == "" {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "setOracleAccount: empty account"))
		}
		sdk.StateSetObject(constants.OracleAccountKey, p.Account)

	case "registerRelayer":
		assertNotPaused()
		var p struct {
			Account string `json:"account"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "registerRelayer: bad payload"))
		}
		if p.Account == "" {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "registerRelayer: empty account"))
		}
		mapping.SetRelayer(p.Account)

	case "deregisterRelayer":
		assertNotPaused()
		var p struct {
			Account string `json:"account"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "deregisterRelayer: bad payload"))
		}
		if p.Account == "" {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "deregisterRelayer: empty account"))
		}
		mapping.UnsetRelayer(p.Account)

	case "clearTestnetState":
		// W4 Cluster E D-E-8 (v19 §AR + v20 §BG LOCKED): chain-gated to
		// testnet via the is_testnet state-key sentinel (set by this
		// contract's initContract when IsTestnet=true; absent on mainnet).
		// Body deletes all PendingSpend entries, resets confirmedNonce +
		// pendingNonce, clears observed-list. Cluster C wraps THIS case
		// via the propose/execute Operational-class (7.2K / 6h) timelock,
		// so even on testnet the call surfaces through the audit trail.
		assertNotPaused()
		if err := mapping.HandleClearTestnetState(); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
		}

	// --------------------------------------------------------------
	// Emergency (Immediate, 0 blocks)
	// --------------------------------------------------------------
	case "pause":
		// pause must NOT have assertNotPaused — it would no-op once
		// already paused, but more importantly the gate exists to keep
		// pause callable at all times (including from within a recovery
		// flow). Just set the sentinel.
		sdk.StateSetObject(constants.PausedKey, "1")

	case "unpause":
		// unpause likewise must always be callable, even when the
		// "paused" sentinel is set.
		sdk.StateDeleteObject(constants.PausedKey)

	default:
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "dispatchAdmin: unknown action "+action))
	}
}

// decodeAddressPayload — setVault payload is either:
//   (a) a JSON-encoded string literal: "\"0x...\""
//   (b) a plain 0x-prefixed hex byte slice
// Pre-fix the wasmexport directly stored *input (the raw string), so for
// compatibility this accepts both forms. The stored value is the canonical
// 0x-prefixed lowercase hex (no quotes).
func decodeAddressPayload(payload []byte) (string, error) {
	if len(payload) == 0 {
		return "", ce.NewContractError(ce.ErrInput, "empty payload")
	}
	// Try JSON string first.
	var s string
	if err := json.Unmarshal(payload, &s); err == nil && s != "" {
		return s, nil
	}
	// Fall back to raw string interpretation.
	return string(payload), nil
}

