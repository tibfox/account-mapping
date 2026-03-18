package current_test

import (
	"eth-mapping-contract/contract/constants"
	"eth-mapping-contract/contract/mapping"
	"fmt"
	"testing"

	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/assert"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
)

const (
	allowanceOwner   = "hive:alice"
	allowanceSpender = "spender_contract"
	allowanceTarget  = "hive:bob"
)

// allowanceKey returns the state key for an allowance entry.
func allowanceKey(owner, spender string) string {
	return constants.AllowancePrefix + owner + constants.DirPathDelimiter + spender
}

// setupAllowanceContract registers a contract and seeds the owner's balance.
func setupAllowanceContract(t *testing.T, balance int64) (*test_utils.ContractTest, string) {
	t.Helper()
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, allowanceOwner, ContractWasm)
	if balance > 0 {
		ct.StateSet(contractId, constants.BalancePrefix+allowanceOwner, encodeBalance(t, balance))
	}
	return &ct, contractId
}

// callApprove calls the approve action as the given owner.
func callApprove(
	t *testing.T,
	ct *test_utils.ContractTest,
	contractId, owner, spender string,
	amount int64,
) test_utils.ContractTestCallResult {
	t.Helper()
	payload, err := tinyjson.Marshal(mapping.AllowanceParams{
		Spender: spender,
		Amount:  fmt.Sprintf("%d", amount),
	})
	if err != nil {
		t.Fatal("marshal approve payload:", err)
	}
	return ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, owner),
		ContractId: contractId,
		Action:     "approve",
		Payload:    payload,
		RcLimit:    1000,
		Caller:     owner,
		Intents:    []contracts.Intent{},
	})
}

// callIncreaseAllowance calls the increaseAllowance action as the given owner.
func callIncreaseAllowance(
	t *testing.T,
	ct *test_utils.ContractTest,
	contractId, owner, spender string,
	amount int64,
) test_utils.ContractTestCallResult {
	t.Helper()
	payload, err := tinyjson.Marshal(mapping.AllowanceParams{
		Spender: spender,
		Amount:  fmt.Sprintf("%d", amount),
	})
	if err != nil {
		t.Fatal("marshal increaseAllowance payload:", err)
	}
	return ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, owner),
		ContractId: contractId,
		Action:     "increaseAllowance",
		Payload:    payload,
		RcLimit:    1000,
		Caller:     owner,
		Intents:    []contracts.Intent{},
	})
}

// callDecreaseAllowance calls the decreaseAllowance action as the given owner.
func callDecreaseAllowance(
	t *testing.T,
	ct *test_utils.ContractTest,
	contractId, owner, spender string,
	amount int64,
) test_utils.ContractTestCallResult {
	t.Helper()
	payload, err := tinyjson.Marshal(mapping.AllowanceParams{
		Spender: spender,
		Amount:  fmt.Sprintf("%d", amount),
	})
	if err != nil {
		t.Fatal("marshal decreaseAllowance payload:", err)
	}
	return ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, owner),
		ContractId: contractId,
		Action:     "decreaseAllowance",
		Payload:    payload,
		RcLimit:    1000,
		Caller:     owner,
		Intents:    []contracts.Intent{},
	})
}

// callTransferFrom simulates a spender contract calling transferFrom on behalf of from.
// The owner (from) must have previously approved the spender.
func callTransferFrom(
	t *testing.T,
	ct *test_utils.ContractTest,
	contractId, spender, from, to string,
	amount int64,
) test_utils.ContractTestCallResult {
	t.Helper()
	payload, err := tinyjson.Marshal(mapping.TransferParams{
		From:   from,
		To:     to,
		Amount: fmt.Sprintf("%d", amount),
	})
	if err != nil {
		t.Fatal("marshal transferFrom payload:", err)
	}
	thisTx := txId
	txId++
	return ct.Call(stateEngine.TxVscCallContract{
		// from's account is the source of funds; RequiredAuths authenticates this tx
		Self: stateEngine.TxSelf{
			TxId:                 fmt.Sprintf("%d", thisTx),
			BlockId:              fmt.Sprintf("%d", thisTx),
			Index:                0,
			OpIndex:              0,
			Timestamp:            "2025-10-14T00:00:00",
			RequiredAuths:        []string{from},
			RequiredPostingAuths: []string{},
		},
		ContractId: contractId,
		Action:     "transferFrom",
		Payload:    payload,
		RcLimit:    1000,
		// spender is the direct caller (a third-party contract)
		Caller:  spender,
		Intents: []contracts.Intent{},
	})
}

// ---------------------------------------------------------------------------
// Approve tests
// ---------------------------------------------------------------------------

// TestApprove verifies that approve writes the correct allowance key to state.
func TestApprove(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)

	r := callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 5000)
	if r.Err != "" {
		t.Fatalf("approve failed: %s: %s", r.Err, r.ErrMsg)
	}
	assert.True(t, r.Success)

	key := allowanceKey(allowanceOwner, allowanceSpender)
	stored := ct.StateGet(contractId, key)
	assert.Equal(t, encodeBalance(t, 5000), stored, "allowance state should equal encoded 5000")
}

// TestApproveOverwrite verifies that a second approve call replaces the previous allowance.
func TestApproveOverwrite(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)

	callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 5000)
	r := callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 1000)
	if r.Err != "" {
		t.Fatalf("second approve failed: %s: %s", r.Err, r.ErrMsg)
	}
	assert.True(t, r.Success)

	key := allowanceKey(allowanceOwner, allowanceSpender)
	assert.Equal(t, encodeBalance(t, 1000), ct.StateGet(contractId, key))
}

// TestApproveToZeroClearsKey verifies that approving 0 removes the allowance key.
func TestApproveToZeroClearsKey(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)

	callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 5000)
	r := callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 0)
	assert.True(t, r.Success)

	key := allowanceKey(allowanceOwner, allowanceSpender)
	assert.Equal(t, "", ct.StateGet(contractId, key), "allowance key should be deleted when set to 0")
}

// TestApproveNegativeAmountFails verifies that approving a negative amount is rejected.
func TestApproveNegativeAmountFails(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)

	r := callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, -100)
	assert.False(t, r.Success, "approve with negative amount should fail")
	assert.NotEmpty(t, r.Err)
}

// TestApproveEmptySpenderFails verifies that approving with an empty spender is rejected.
func TestApproveEmptySpenderFails(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)

	payload, err := tinyjson.Marshal(mapping.AllowanceParams{
		Spender: "",
		Amount:  "5000",
	})
	if err != nil {
		t.Fatal(err)
	}
	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, allowanceOwner),
		ContractId: contractId,
		Action:     "approve",
		Payload:    payload,
		RcLimit:    1000,
		Caller:     allowanceOwner,
		Intents:    []contracts.Intent{},
	})
	assert.False(t, r.Success, "approve with empty spender should fail")
	assert.NotEmpty(t, r.Err)
}

// TestApproveSelfAsSpenderFails verifies that approving oneself as spender is rejected.
func TestApproveSelfAsSpenderFails(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)

	r := callApprove(t, ct, contractId, allowanceOwner, allowanceOwner, 5000)
	assert.False(t, r.Success, "approve self as spender should fail")
	assert.NotEmpty(t, r.Err)
}

// ---------------------------------------------------------------------------
// IncreaseAllowance tests
// ---------------------------------------------------------------------------

// TestIncreaseAllowance verifies that increaseAllowance adds to an existing allowance.
func TestIncreaseAllowance(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)

	callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 1000)
	r := callIncreaseAllowance(t, ct, contractId, allowanceOwner, allowanceSpender, 500)
	if r.Err != "" {
		t.Fatalf("increaseAllowance failed: %s: %s", r.Err, r.ErrMsg)
	}
	assert.True(t, r.Success)

	key := allowanceKey(allowanceOwner, allowanceSpender)
	assert.Equal(t, encodeBalance(t, 1500), ct.StateGet(contractId, key))
}

// TestIncreaseAllowanceFromZero verifies that increaseAllowance works from no prior approval.
func TestIncreaseAllowanceFromZero(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)

	r := callIncreaseAllowance(t, ct, contractId, allowanceOwner, allowanceSpender, 800)
	if r.Err != "" {
		t.Fatalf("increaseAllowance from zero failed: %s: %s", r.Err, r.ErrMsg)
	}
	assert.True(t, r.Success)

	key := allowanceKey(allowanceOwner, allowanceSpender)
	assert.Equal(t, encodeBalance(t, 800), ct.StateGet(contractId, key))
}

// TestIncreaseAllowanceZeroAmountFails verifies that increasing by zero is rejected.
func TestIncreaseAllowanceZeroAmountFails(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)

	r := callIncreaseAllowance(t, ct, contractId, allowanceOwner, allowanceSpender, 0)
	assert.False(t, r.Success, "increaseAllowance with zero amount should fail")
	assert.NotEmpty(t, r.Err)
}

// TestIncreaseAllowanceEmptySpenderFails verifies that increasing with empty spender is rejected.
func TestIncreaseAllowanceEmptySpenderFails(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)

	payload, err := tinyjson.Marshal(mapping.AllowanceParams{
		Spender: "",
		Amount:  "500",
	})
	if err != nil {
		t.Fatal(err)
	}
	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, allowanceOwner),
		ContractId: contractId,
		Action:     "increaseAllowance",
		Payload:    payload,
		RcLimit:    1000,
		Caller:     allowanceOwner,
		Intents:    []contracts.Intent{},
	})
	assert.False(t, r.Success, "increaseAllowance with empty spender should fail")
	assert.NotEmpty(t, r.Err)
}

// ---------------------------------------------------------------------------
// DecreaseAllowance tests
// ---------------------------------------------------------------------------

// TestDecreaseAllowance verifies that decreaseAllowance subtracts from an existing allowance.
func TestDecreaseAllowance(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)

	callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 1000)
	r := callDecreaseAllowance(t, ct, contractId, allowanceOwner, allowanceSpender, 400)
	if r.Err != "" {
		t.Fatalf("decreaseAllowance failed: %s: %s", r.Err, r.ErrMsg)
	}
	assert.True(t, r.Success)

	key := allowanceKey(allowanceOwner, allowanceSpender)
	assert.Equal(t, encodeBalance(t, 600), ct.StateGet(contractId, key))
}

// TestDecreaseAllowanceToZeroClearsKey verifies that decreasing to exactly 0 deletes the key.
func TestDecreaseAllowanceToZeroClearsKey(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)

	callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 1000)
	r := callDecreaseAllowance(t, ct, contractId, allowanceOwner, allowanceSpender, 1000)
	assert.True(t, r.Success)

	key := allowanceKey(allowanceOwner, allowanceSpender)
	assert.Equal(t, "", ct.StateGet(contractId, key), "allowance key should be deleted when decreased to 0")
}

// TestDecreaseAllowanceBelowZeroFails verifies that decreasing below zero is rejected.
func TestDecreaseAllowanceBelowZeroFails(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)

	callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 500)
	r := callDecreaseAllowance(t, ct, contractId, allowanceOwner, allowanceSpender, 1000)
	assert.False(t, r.Success, "decreaseAllowance below zero should fail")
	assert.NotEmpty(t, r.Err)
}

// TestDecreaseAllowanceEmptySpenderFails verifies that decreasing with empty spender is rejected.
func TestDecreaseAllowanceEmptySpenderFails(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 0)

	payload, err := tinyjson.Marshal(mapping.AllowanceParams{
		Spender: "",
		Amount:  "500",
	})
	if err != nil {
		t.Fatal(err)
	}
	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, allowanceOwner),
		ContractId: contractId,
		Action:     "decreaseAllowance",
		Payload:    payload,
		RcLimit:    1000,
		Caller:     allowanceOwner,
		Intents:    []contracts.Intent{},
	})
	assert.False(t, r.Success, "decreaseAllowance with empty spender should fail")
	assert.NotEmpty(t, r.Err)
}

// ---------------------------------------------------------------------------
// TransferFrom tests
// ---------------------------------------------------------------------------

// TestTransferFrom verifies that an approved spender can transfer tokens from the owner.
func TestTransferFrom(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 10000)

	// Owner approves spender for 5000
	ar := callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 5000)
	if !ar.Success {
		t.Fatalf("approve failed: %s: %s", ar.Err, ar.ErrMsg)
	}

	// Spender transfers 3000 from owner to target
	r := callTransferFrom(t, ct, contractId, allowanceSpender, allowanceOwner, allowanceTarget, 3000)
	if r.Err != "" {
		t.Fatalf("transferFrom failed: %s: %s", r.Err, r.ErrMsg)
	}
	assert.True(t, r.Success)

	// Owner balance should be 10000 - 3000 = 7000
	assert.Equal(t, encodeBalance(t, 7000), ct.StateGet(contractId, constants.BalancePrefix+allowanceOwner))
	// Target should have received 3000
	assert.Equal(t, encodeBalance(t, 3000), ct.StateGet(contractId, constants.BalancePrefix+allowanceTarget))
	// Remaining allowance should be 5000 - 3000 = 2000
	assert.Equal(t, encodeBalance(t, 2000), ct.StateGet(contractId, allowanceKey(allowanceOwner, allowanceSpender)))
}

// TestTransferFromExhaustsAllowance verifies a spender can spend up to the exact allowance amount.
func TestTransferFromExhaustsAllowance(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 10000)

	callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 4000)

	r := callTransferFrom(t, ct, contractId, allowanceSpender, allowanceOwner, allowanceTarget, 4000)
	if r.Err != "" {
		t.Fatalf("transferFrom failed: %s: %s", r.Err, r.ErrMsg)
	}
	assert.True(t, r.Success)

	// Allowance key should be deleted (set to 0)
	assert.Equal(t, "", ct.StateGet(contractId, allowanceKey(allowanceOwner, allowanceSpender)),
		"allowance key should be deleted after full spend")
	assert.Equal(t, encodeBalance(t, 6000), ct.StateGet(contractId, constants.BalancePrefix+allowanceOwner))
}

// TestTransferFromExceedsAllowanceFails verifies that spending more than the allowance is rejected.
func TestTransferFromExceedsAllowanceFails(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 10000)

	callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 1000)

	r := callTransferFrom(t, ct, contractId, allowanceSpender, allowanceOwner, allowanceTarget, 2000)
	assert.False(t, r.Success, "transferFrom exceeding allowance should fail")
	assert.NotEmpty(t, r.Err)

	// Owner balance and allowance should be unchanged
	assert.Equal(t, encodeBalance(t, 10000), ct.StateGet(contractId, constants.BalancePrefix+allowanceOwner))
	assert.Equal(t, encodeBalance(t, 1000), ct.StateGet(contractId, allowanceKey(allowanceOwner, allowanceSpender)))
}

// TestTransferFromNoAllowanceFails verifies that a spender with no approval cannot transfer.
func TestTransferFromNoAllowanceFails(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 10000)

	r := callTransferFrom(t, ct, contractId, allowanceSpender, allowanceOwner, allowanceTarget, 1000)
	assert.False(t, r.Success, "transferFrom with no allowance should fail")
	assert.NotEmpty(t, r.Err)

	// Owner balance should be unchanged
	assert.Equal(t, encodeBalance(t, 10000), ct.StateGet(contractId, constants.BalancePrefix+allowanceOwner))
}

// TestTransferFromAllowanceDecrements verifies allowance is decremented across multiple calls.
func TestTransferFromAllowanceDecrements(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 10000)

	callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 6000)

	// First spend: 2000
	r1 := callTransferFrom(t, ct, contractId, allowanceSpender, allowanceOwner, allowanceTarget, 2000)
	if !r1.Success {
		t.Fatalf("first transferFrom failed: %s: %s", r1.Err, r1.ErrMsg)
	}
	assert.Equal(t, encodeBalance(t, 4000), ct.StateGet(contractId, allowanceKey(allowanceOwner, allowanceSpender)))

	// Second spend: 3000
	r2 := callTransferFrom(t, ct, contractId, allowanceSpender, allowanceOwner, allowanceTarget, 3000)
	if !r2.Success {
		t.Fatalf("second transferFrom failed: %s: %s", r2.Err, r2.ErrMsg)
	}
	assert.Equal(t, encodeBalance(t, 1000), ct.StateGet(contractId, allowanceKey(allowanceOwner, allowanceSpender)))

	// Third spend: 2000 — exceeds remaining allowance of 1000
	r3 := callTransferFrom(t, ct, contractId, allowanceSpender, allowanceOwner, allowanceTarget, 2000)
	assert.False(t, r3.Success, "third transferFrom should fail: allowance exhausted")
}

// TestTransferFromInsufficientBalanceFails verifies that transferFrom fails when
// the owner has insufficient balance, even if allowance is sufficient.
func TestTransferFromInsufficientBalanceFails(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 1000)

	// Approve more than balance
	callApprove(t, ct, contractId, allowanceOwner, allowanceSpender, 5000)

	r := callTransferFrom(t, ct, contractId, allowanceSpender, allowanceOwner, allowanceTarget, 3000)
	assert.False(t, r.Success, "transferFrom should fail when owner has insufficient balance")
	assert.NotEmpty(t, r.Err)

	// Balance unchanged
	assert.Equal(t, encodeBalance(t, 1000), ct.StateGet(contractId, constants.BalancePrefix+allowanceOwner))
}

// ---------------------------------------------------------------------------
// Direct transfer tests
// ---------------------------------------------------------------------------

// TestDirectTransferNoAllowanceRequired verifies that a caller transferring their own tokens
// does not require an allowance.
func TestDirectTransferNoAllowanceRequired(t *testing.T) {
	ct, contractId := setupAllowanceContract(t, 5000)

	payload, err := tinyjson.Marshal(mapping.TransferParams{
		To:     allowanceTarget,
		Amount: "3000",
	})
	if err != nil {
		t.Fatal(err)
	}
	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, allowanceOwner),
		ContractId: contractId,
		Action:     "transfer",
		Payload:    payload,
		RcLimit:    1000,
		Caller:     allowanceOwner,
		Intents:    []contracts.Intent{},
	})
	if r.Err != "" {
		t.Fatalf("direct transfer failed: %s: %s", r.Err, r.ErrMsg)
	}
	assert.True(t, r.Success)
	assert.Equal(t, encodeBalance(t, 2000), ct.StateGet(contractId, constants.BalancePrefix+allowanceOwner))
	assert.Equal(t, encodeBalance(t, 3000), ct.StateGet(contractId, constants.BalancePrefix+allowanceTarget))
}
