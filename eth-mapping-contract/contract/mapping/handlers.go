package mapping

import (
	"eth-mapping-contract/contract/constants"
	ce "eth-mapping-contract/contract/contracterrors"
	"eth-mapping-contract/sdk"
	"net/url"
	"strconv"
	"strings"

	"github.com/CosmWasm/tinyjson"
)

// HandleMap processes verified ETH deposits submitted by the oracle.
// For each deposit, it checks for duplicates, parses the instruction,
// and either credits the recipient's balance (deposit) or triggers
// a DEX swap (swap-via-map).
func HandleMap(params *MapParams) error {
	env := sdk.GetEnv()
	routerId := ""

	for _, deposit := range params.Deposits {
		if deposit.TxHash == "" {
			return ce.NewContractError(ce.ErrInput, "tx_hash required for each deposit")
		}
		if deposit.Amount == "" {
			return ce.NewContractError(ce.ErrInput, "amount required for each deposit")
		}
		amount, err := strconv.ParseInt(deposit.Amount, 10, 64)
		if err != nil {
			return ce.WrapContractError(ce.ErrInput, err, "invalid deposit amount")
		}
		if amount <= 0 {
			return ce.NewContractError(ce.ErrInput, "deposit amount must be positive")
		}

		// Duplicate detection — skip already-observed deposits
		observedKey := constants.ObservedPrefix + deposit.TxHash
		alreadyObserved := sdk.StateGetObject(observedKey)
		if alreadyObserved != nil && *alreadyObserved != "" {
			continue
		}
		sdk.StateSetObject(observedKey, "1")

		// Parse instruction to determine deposit type
		mappingType, recipient, assetOut, err := parseInstruction(deposit.Instruction)
		if err != nil {
			return err
		}

		switch mappingType {
		case MapDeposit:
			if err := incAccBalance(recipient, amount); err != nil {
				return ce.Prepend(err, "error crediting deposit balance")
			}
			sdk.Log(createDepositLog(recipient, deposit.Sender, amount))

		case MapSwap:
			if routerId == "" {
				r := sdk.StateGetObject(constants.RouterContractIdKey)
				if r == nil || *r == "" {
					return ce.NewContractError(ce.ErrInitialization, "router contract not initialized")
				}
				routerId = *r
			}

			sender := env.Sender.Address.String()
			if err := incAccBalance(sender, amount); err != nil {
				return ce.Prepend(err, "error crediting sender balance for swap")
			}

			instruction := DexInstruction{
				Type:      "swap",
				Version:   "1.0.0",
				AssetIn:   "ETH",
				AmountIn:  deposit.Amount,
				AssetOut:  assetOut,
				Recipient: recipient,
			}
			instrJson, err := tinyjson.Marshal(instruction)
			if err != nil {
				return ce.NewContractError(ce.ErrJson, "error marshalling swap instruction: "+err.Error())
			}

			// Approve Router to spend the user's freshly-credited tokens.
			setAllowance(sender, routerId, amount)

			sdk.ContractCall(routerId, "execute", string(instrJson), &sdk.ContractCallOptions{})
			// Clean up remaining allowance after swap
			setAllowance(sender, routerId, 0)
		}
	}

	return nil
}

// parseInstruction decodes a URL-encoded instruction string into a mapping type,
// recipient address, and optional output asset (for swaps).
func parseInstruction(instruction string) (MappingType, string, string, error) {
	if instruction == "" {
		return "", "", "", ce.NewContractError(ce.ErrInput, "deposit instruction required")
	}

	values, err := url.ParseQuery(instruction)
	if err != nil {
		return "", "", "", ce.WrapContractError(ce.ErrInput, err, "invalid instruction format")
	}

	// Check for deposit instruction
	if depositTo := values.Get(constants.DepositToKey); depositTo != "" {
		recipientAddr := sdk.Address(depositTo)
		if !recipientAddr.IsValid() {
			return "", "", "", ce.NewContractError(ce.ErrInput, "invalid deposit_to address: "+depositTo)
		}
		return MapDeposit, depositTo, "", nil
	}

	// Check for swap instruction
	if swapTo := values.Get(constants.SwapToKey); swapTo != "" {
		assetOut := values.Get(constants.SwapAssetOut)
		if assetOut == "" {
			return "", "", "", ce.NewContractError(ce.ErrInput, "swap_asset_out required for swap instruction")
		}
		recipientAddr := sdk.Address(swapTo)
		if !recipientAddr.IsValid() {
			return "", "", "", ce.NewContractError(ce.ErrInput, "invalid swap_to address: "+swapTo)
		}
		return MapSwap, swapTo, assetOut, nil
	}

	return "", "", "", ce.NewContractError(ce.ErrInput, "instruction must contain deposit_to or swap_to")
}

// createDepositLog builds a structured deposit log entry.
func createDepositLog(to, from string, amount int64) string {
	var b strings.Builder
	b.Grow(128)
	b.WriteString("dep")
	b.WriteString(constants.LogDelimiter)
	b.WriteString("t")
	b.WriteString(constants.LogKeyDelimiter)
	b.WriteString(to)
	b.WriteString(constants.LogDelimiter)
	b.WriteString("f")
	b.WriteString(constants.LogKeyDelimiter)
	b.WriteString(from)
	b.WriteString(constants.LogDelimiter)
	b.WriteString("a")
	b.WriteString(constants.LogKeyDelimiter)
	var buf [20]byte
	b.Write(strconv.AppendInt(buf[:0], amount, 10))
	return b.String()
}

// HandleTransfer moves funds between accounts within the contract.
// If From is set, uses allowance-based deduction (transferFrom pattern).
func HandleTransfer(params *TransferParams) error {
	env := sdk.GetEnv()
	err := checkAuth(env)
	if err != nil {
		return err
	}
	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil {
		return ce.WrapContractError(ce.ErrInput, err, "invalid amount value")
	}
	if amount <= 0 {
		return ce.NewContractError(ce.ErrInput, "amount must be positive")
	}
	if params.To == "" {
		return ce.NewContractError(ce.ErrInput, "recipient address required")
	}

	recipientAddress := sdk.Address(params.To)
	if !recipientAddress.IsValid() {
		return ce.NewContractError(ce.ErrInput, "invalid recipient address")
	}

	from := params.From
	if from == "" {
		from = env.Caller.String()
	}
	err = checkAndDeductBalance(env, from, amount)
	if err != nil {
		return err
	}

	recipientBal := getAccBal(params.To)
	newBal, err := safeAdd64(recipientBal, amount)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "error incrementing user balance")
	}
	setAccBal(params.To, newBal)

	return nil
}

// HandleUnmap processes a withdrawal request, debiting the user's balance.
// The actual ETH transfer is handled by the mapping bot.
func HandleUnmap(params *TransferParams) error {
	env := sdk.GetEnv()
	err := checkAuth(env)
	if err != nil {
		return err
	}
	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil {
		return ce.WrapContractError(ce.ErrInput, err, "invalid amount value")
	}
	if amount <= 0 {
		return ce.NewContractError(ce.ErrInput, "amount must be positive")
	}
	if params.To == "" {
		return ce.NewContractError(ce.ErrInput, "destination address required")
	}

	ethNet := EthNetwork{}
	if !ethNet.ValidateAddress(params.To) {
		return ce.NewContractError(ce.ErrInput, "invalid ETH address")
	}

	err = checkAndDeductBalance(env, env.Caller.String(), amount)
	if err != nil {
		return err
	}

	return nil
}

// HandleApprove sets the spending allowance for spender to spend owner's tokens.
func HandleApprove(owner, spender string, amount int64) {
	setAllowance(owner, spender, amount)
}

// HandleIncreaseAllowance increases spender's allowance by amount.
func HandleIncreaseAllowance(owner, spender string, amount int64) error {
	current := getAllowance(owner, spender)
	newAmount, err := safeAdd64(current, amount)
	if err != nil {
		return ce.WrapContractError(ce.ErrArithmetic, err, "overflow increasing allowance")
	}
	setAllowance(owner, spender, newAmount)
	return nil
}

// HandleDecreaseAllowance decreases spender's allowance by amount; reverts if it would go below zero.
func HandleDecreaseAllowance(owner, spender string, amount int64) error {
	current := getAllowance(owner, spender)
	newAmount, err := safeSubtract64(current, amount)
	if err != nil || newAmount < 0 {
		return ce.NewContractError(ce.ErrArithmetic, "allowance cannot go below zero")
	}
	setAllowance(owner, spender, newAmount)
	return nil
}
