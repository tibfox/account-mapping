package main

import (
	"encoding/hex"
	"eth-mapping-contract/contract/blocklist"
	"eth-mapping-contract/contract/constants"
	ce "eth-mapping-contract/contract/contracterrors"
	"eth-mapping-contract/contract/mapping"
	_ "eth-mapping-contract/sdk"
	"strconv"
	"strings"

	"eth-mapping-contract/sdk"

	"github.com/CosmWasm/tinyjson"
)

// passed via ldflags, will compile for testnet when set to "testnet"
var NetworkMode string

func checkAdmin() {
	var adminAddress string
	if constants.IsTestnet(NetworkMode) {
		adminAddress = *sdk.GetEnvKey("contract.owner")
	} else {
		adminAddress = constants.OracleAddress
	}
	if sdk.GetEnv().Caller.String() != adminAddress {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrNoPermission, "this action must be performed by a contract administrator"),
		)
	}
}

//go:wasmexport seedBlocks
func SeedBlocks(blockSeedInput *string) *string {
	checkAdmin()

	var seedParams blocklist.SeedBlocksParams
	err := tinyjson.Unmarshal([]byte(*blockSeedInput), &seedParams)
	if err != nil {
		ce.CustomAbort(ce.WrapContractError(ce.ErrJson, err))
	}

	newLastHeight, err := blocklist.HandleSeedBlocks(seedParams, constants.IsTestnet(NetworkMode))
	if err != nil {
		ce.CustomAbort(err)
	}

	outMsg := "last height: " + strconv.FormatUint(uint64(newLastHeight), 10)
	return &outMsg
}

//go:wasmexport addBlocks
func AddBlocks(addBlocksInput *string) *string {
	checkAdmin()

	var addBlocksObj blocklist.AddBlocksParams
	err := tinyjson.Unmarshal([]byte(*addBlocksInput), &addBlocksObj)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	var resultBuilder strings.Builder
	lastHeight, added, err := blocklist.HandleAddBlocks(addBlocksObj.Blocks, NetworkMode)
	if err != nil {
		if err != blocklist.ErrorSequenceIncorrect {
			ce.CustomAbort(err)
		} else {
			resultBuilder.WriteString("error adding blocks: " + err.Error())
			resultBuilder.WriteString(", added " + strconv.FormatUint(uint64(added), 10) + " blocks, ")
		}
	}
	resultBuilder.WriteString("last height: " + strconv.FormatUint(uint64(lastHeight), 10))

	blocklist.LastHeightToState(lastHeight)

	result := resultBuilder.String()
	return &result
}

// Map processes verified ETH deposits submitted by the oracle/admin.
// Payload: JSON with deposit array
// {"deposits": [{"tx_hash": "0xabc...", "amount": "1000000", "sender": "0x123...", "instruction": "deposit_to=hive:user"}]}
//
//go:wasmexport map
func Map(incomingTx *string) *string {
	checkAdmin()

	if incomingTx == nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "payload required"))
	}

	var mapParams mapping.MapParams
	err := tinyjson.Unmarshal([]byte(*incomingTx), &mapParams)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	if len(mapParams.Deposits) == 0 {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "at least one deposit required"))
	}

	err = mapping.HandleMap(&mapParams)
	if err != nil {
		ce.CustomAbort(err)
	}

	return mapping.StrPtr("0")
}

//go:wasmexport unmap
func Unmap(tx *string) *string {
	var unmapInstructions mapping.TransferParams
	err := tinyjson.Unmarshal([]byte(*tx), &unmapInstructions)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}
	if unmapInstructions.To == "" {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, "destination address required"),
		)
	}

	err = mapping.HandleUnmap(&unmapInstructions)
	if err != nil {
		ce.CustomAbort(err)
	}

	return mapping.StrPtr("0")
}

// Transfers funds from the Caller (immediate caller of the contract)
//
//go:wasmexport transfer
func Transfer(tx *string) *string {
	var transferInstructions mapping.TransferParams
	err := tinyjson.Unmarshal([]byte(*tx), &transferInstructions)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	err = mapping.HandleTransfer(&transferInstructions)
	if err != nil {
		ce.CustomAbort(err)
	}

	return mapping.StrPtr("0")
}

// Draws funds from a third-party account that has approved the caller.
//
//go:wasmexport transferFrom
func TransferFrom(tx *string) *string {
	var drawInstructions mapping.TransferParams
	err := tinyjson.Unmarshal([]byte(*tx), &drawInstructions)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	err = mapping.HandleTransfer(&drawInstructions)
	if err != nil {
		ce.CustomAbort(err)
	}

	return mapping.StrPtr("0")
}

// Sets a spending allowance for a spender contract to use the caller's tokens.
//
//go:wasmexport approve
func Approve(input *string) *string {
	env := sdk.GetEnv()
	var params mapping.AllowanceParams
	err := tinyjson.Unmarshal([]byte(*input), &params)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput))
	}
	if params.Spender == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "spender address required"))
	}
	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "invalid amount value"))
	}
	if amount < 0 {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "allowance amount must be non-negative"))
	}
	if params.Spender == env.Caller.String() {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "cannot approve self as spender"))
	}
	mapping.HandleApprove(env.Caller.String(), params.Spender, amount)
	return mapping.StrPtr("0")
}

// Increases the spending allowance for a spender contract.
//
//go:wasmexport increaseAllowance
func IncreaseAllowance(input *string) *string {
	env := sdk.GetEnv()
	var params mapping.AllowanceParams
	err := tinyjson.Unmarshal([]byte(*input), &params)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput))
	}
	if params.Spender == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "spender address required"))
	}
	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "invalid amount value"))
	}
	if amount <= 0 {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "amount must be positive"))
	}
	err = mapping.HandleIncreaseAllowance(env.Caller.String(), params.Spender, amount)
	if err != nil {
		ce.CustomAbort(err)
	}
	return mapping.StrPtr("0")
}

// Decreases the spending allowance for a spender contract.
//
//go:wasmexport decreaseAllowance
func DecreaseAllowance(input *string) *string {
	env := sdk.GetEnv()
	var params mapping.AllowanceParams
	err := tinyjson.Unmarshal([]byte(*input), &params)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput))
	}
	if params.Spender == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "spender address required"))
	}
	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "invalid amount value"))
	}
	if amount <= 0 {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "amount must be positive"))
	}
	err = mapping.HandleDecreaseAllowance(env.Caller.String(), params.Spender, amount)
	if err != nil {
		ce.CustomAbort(err)
	}
	return mapping.StrPtr("0")
}

func validatePublicKey(keyHex string) error {
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return ce.WrapContractError(ce.ErrInvalidHex, err)
	}
	if len(keyBytes) != 33 && len(keyBytes) != 65 {
		return ce.NewContractError(
			ce.ErrInput,
			"invalid key length: expected 33 or 65 bytes, got "+strconv.Itoa(len(keyBytes)),
		)
	}
	if len(keyBytes) == 33 && (keyBytes[0] != 0x02 && keyBytes[0] != 0x03) {
		return ce.NewContractError(ce.ErrInput, "invalid compressed key prefix")
	}
	return nil
}

//go:wasmexport registerPublicKey
func RegisterPublicKey(keyStr *string) *string {
	env := sdk.GetEnv()
	// leave this as owner always
	if env.Caller.String() != *sdk.GetEnvKey("contract.owner") {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrNoPermission, "action must be performed by the contract owner"),
		)
	}

	var keys mapping.PublicKeys
	err := tinyjson.Unmarshal([]byte(*keyStr), &keys)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	var resultBuilder strings.Builder

	if keys.PrimaryPubKey != "" {
		err := validatePublicKey(keys.PrimaryPubKey)
		if err != nil {
			ce.CustomAbort(ce.Prepend(err, "error registering primary public key"))
		}
		existingPrimary := sdk.StateGetObject(constants.PrimaryPublicKeyStateKey)
		if *existingPrimary == "" || constants.IsTestnet(NetworkMode) {
			sdk.StateSetObject(constants.PrimaryPublicKeyStateKey, keys.PrimaryPubKey)
			resultBuilder.WriteString("set primary key to: " + keys.PrimaryPubKey)
		} else {
			resultBuilder.WriteString("primary key already registered: " + *existingPrimary)
		}
	}

	if keys.BackupPubKey != "" {
		err := validatePublicKey(keys.BackupPubKey)
		if err != nil {
			ce.CustomAbort(ce.Prepend(err, "error registering backup public key"))
		}
		if resultBuilder.Len() > 0 {
			resultBuilder.WriteString(", ")
		}
		existingBackup := sdk.StateGetObject(constants.BackupPublicKeyStateKey)
		if *existingBackup == "" || constants.IsTestnet(NetworkMode) {
			sdk.StateSetObject(constants.BackupPublicKeyStateKey, keys.BackupPubKey)
			resultBuilder.WriteString("set backup key to: " + keys.BackupPubKey)
		} else {
			resultBuilder.WriteString("backup key already registered: " + *existingBackup)
		}
	}

	return mapping.StrPtr(resultBuilder.String())
}

//go:wasmexport registerRouter
func RegisterRouter(input *string) *string {
	env := sdk.GetEnv()
	// leave this as owner always
	if env.Caller.String() != *sdk.GetEnvKey("contract.owner") {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrNoPermission, "action must be performed by the contract owner"),
		)
	}

	var router mapping.RouterContract
	err := tinyjson.Unmarshal([]byte(*input), &router)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	var resultBuilder strings.Builder

	if router.ContractId != "" {
		existingPrimary := sdk.StateGetObject(constants.RouterContractIdKey)
		if *existingPrimary == "" || constants.IsTestnet(NetworkMode) {
			sdk.StateSetObject(constants.RouterContractIdKey, router.ContractId)
			resultBuilder.WriteString("set router contract ID to: " + router.ContractId)
		} else {
			resultBuilder.WriteString("router contract ID already registered: " + *existingPrimary)
		}
	}

	return mapping.StrPtr(resultBuilder.String())
}
