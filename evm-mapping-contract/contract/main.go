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
// these two functions MUST remain separate. checkOwner is called from
// the propose/execute dispatcher; the Hive L1 2-of-3 multisig is
// enforced BEFORE the call reaches the contract. checkAdmin is the
// legacy name kept for compile compatibility with prior touch-points.
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

// checkOracleAccount — W4 Cluster C v20 §BD: dedicated gate for `addBlocks`
// ONLY. Owner accepted too so the pre-setOracleAccount state does not
// deadlock the oracle feed.
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
// touched by the propose/execute migration per W1 §D-C-9.
func assertNotPaused() {
	if err := mapping.AssertNotPaused(); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
}

// -----------------------------------------------------------------------------
// initContract — W4 Cluster C v21 SERIOUS-2 + NOTABLE-1.
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
	var params initContractParams
	if input != nil && *input != "" {
		_ = json.Unmarshal([]byte(*input), &params)
	}
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
	if err := mapping.HandleMap(&params, vault(), chainId()); err != nil {
		ce.CustomAbort(ce.WrapContractError(ce.ErrInput, err))
	}
	return nil
}

//go:wasmexport unmapETH
func unmapETH(input *string) *string {
	var params mapping.TransferParams
	json.Unmarshal([]byte(*input), &params)
	if _, err := mapping.HandleUnmapETH(&params, vault(), chainId()); err != nil {
		ce.CustomAbort(err)
	}
	return nil
}

//go:wasmexport unmapERC20
func unmapERC20(input *string) *string {
	var params mapping.TransferParams
	json.Unmarshal([]byte(*input), &params)
	if _, err := mapping.HandleUnmapERC20(&params, vault(), chainId()); err != nil {
		ce.CustomAbort(err)
	}
	return nil
}

//go:wasmexport confirmSpend
func confirmSpend(input *string) *string {
	var req mapping.ConfirmSpendRequest
	json.Unmarshal([]byte(*input), &req)
	// W4 Cluster F (in a later commit) will drop the vaultAddress parameter
	// and read ps.VaultAtQueue instead. For this commit the signature
	// still takes vault().
	if err := mapping.HandleConfirmSpend(&req, vault(), chainId()); err != nil {
		ce.CustomAbort(err)
	}
	return nil
}

//go:wasmexport transfer
func transfer(input *string) *string {
	var params mapping.TransferParams
	json.Unmarshal([]byte(*input), &params)
	if err := mapping.HandleTransfer(&params); err != nil {
		ce.CustomAbort(err)
	}
	return nil
}

//go:wasmexport transferFrom
func transferFrom(input *string) *string {
	var params mapping.TransferParams
	json.Unmarshal([]byte(*input), &params)
	if err := mapping.HandleTransferFrom(&params); err != nil {
		ce.CustomAbort(err)
	}
	return nil
}

//go:wasmexport approve
func approve(input *string) *string {
	var params mapping.AllowanceParams
	json.Unmarshal([]byte(*input), &params)
	if err := mapping.HandleApprove(&params); err != nil {
		ce.CustomAbort(err)
	}
	return nil
}

//go:wasmexport unmapFrom
func unmapFrom(input *string) *string {
	var params mapping.TransferParams
	json.Unmarshal([]byte(*input), &params)
	if err := mapping.HandleUnmapFrom(&params, vault(), chainId()); err != nil {
		ce.CustomAbort(err)
	}
	return nil
}

//go:wasmexport increaseAllowance
func increaseAllowance(input *string) *string {
	var params mapping.AllowanceParams
	json.Unmarshal([]byte(*input), &params)
	if err := mapping.HandleIncreaseAllowance(&params); err != nil {
		ce.CustomAbort(err)
	}
	return nil
}

//go:wasmexport decreaseAllowance
func decreaseAllowance(input *string) *string {
	var params mapping.AllowanceParams
	json.Unmarshal([]byte(*input), &params)
	if err := mapping.HandleDecreaseAllowance(&params); err != nil {
		ce.CustomAbort(err)
	}
	return nil
}

//go:wasmexport getInfo
func getInfo(_ *string) *string { return nil }

// -----------------------------------------------------------------------------
// addBlocks — EXEMPT from propose/execute per W1 §D-C-8 (v20 §BD).
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
// expireWithdrawal: CRIT #26 D-E-3 permissionless after WithdrawalExpiryWindow.
// cancelMyWithdrawal: CRIT #26 companion (only ps.From + mandatory proof).
// confirmSpendSchema: CRIT #5 D-E-1 schema introspection for the bot.
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

//go:wasmexport confirmSpendSchema
func confirmSpendSchema(_ *string) *string {
	s := mapping.ConfirmSpendSchemaJSON
	return &s
}

// -----------------------------------------------------------------------------
// dispatchAdmin — invoked from execute() AFTER the timelock has elapsed.
// W4 Cluster E lifecycle handlers (expireWithdrawal/cancelMyWithdrawal/
// confirmSpendSchema + clearTestnetState) land in a subsequent commit.
// -----------------------------------------------------------------------------

func dispatchAdmin(action string, payload []byte) {
	switch action {

	// Fund-affecting (Long, 400K blocks)
	case "setVault":
		assertNotPaused()
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
		// W4 Cluster F flag 1 lands the body switch to TssRenewKey in a
		// subsequent commit. Stays as TssCreateKey here for compile parity
		// with base behavior.
		assertNotPaused()
		sdk.TssCreateKey("primary", "ecdsa", 365)

	// Operator-tactical (28.8K blocks, 24h)
	case "registerPublicKey":
		assertNotPaused()
		sdk.StateSetObject(constants.PrimaryPublicKeyKey, string(payload))

	case "replaceBlock":
		assertNotPaused()
		var entry blocklist.AddBlockEntry
		if err := json.Unmarshal(payload, &entry); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "replaceBlock: bad payload"))
		}
		if err := blocklist.HandleReplaceBlock(&entry, chainId()); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
		}

	case "replaceWithdrawal":
		assertNotPaused()
		if err := mapping.HandleReplaceWithdrawal(vault(), chainId()); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
		}

	case "clearNonce":
		assertNotPaused()
		var p mapping.ClearNonceParams
		if err := json.Unmarshal(payload, &p); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "clearNonce: bad payload"))
		}
		if err := mapping.HandleClearNonce(vault(), chainId(), p.Proof); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
		}

	// Operational (7.2K blocks, 6h)
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
		// W4 Cluster E D-E-8 chain-gated handler.
		assertNotPaused()
		if err := mapping.HandleClearTestnetState(); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
		}

	// Emergency (Immediate, 0 blocks)
	case "pause":
		sdk.StateSetObject(constants.PausedKey, "1")

	case "unpause":
		sdk.StateDeleteObject(constants.PausedKey)

	default:
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "dispatchAdmin: unknown action "+action))
	}
}

// decodeAddressPayload — setVault payload is either a JSON-encoded string
// literal or a plain 0x-prefixed hex byte slice.
func decodeAddressPayload(payload []byte) (string, error) {
	if len(payload) == 0 {
		return "", ce.NewContractError(ce.ErrInput, "empty payload")
	}
	var s string
	if err := json.Unmarshal(payload, &s); err == nil && s != "" {
		return s, nil
	}
	return string(payload), nil
}
