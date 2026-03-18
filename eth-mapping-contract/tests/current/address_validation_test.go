package current_test

import (
	"eth-mapping-contract/contract/constants"
	"eth-mapping-contract/contract/mapping"
	"testing"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/assert"
)

// setupAddrContract registers a contract with a funded sender.
func setupAddrContract(t *testing.T, balance int64) (*test_utils.ContractTest, string) {
	t.Helper()
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:testuser", ContractWasm)
	if balance > 0 {
		ct.StateSet(contractId, constants.BalancePrefix+"hive:testuser", encodeBalance(t, balance))
	}
	return &ct, contractId
}

// callTransfer is a helper that calls the transfer action.
func callTransfer(
	t *testing.T,
	ct *test_utils.ContractTest,
	contractId, caller, to, amount string,
) test_utils.ContractTestCallResult {
	t.Helper()
	payload, err := tinyjson.Marshal(mapping.TransferParams{
		To:     to,
		Amount: amount,
	})
	if err != nil {
		t.Fatal("marshal transfer payload:", err)
	}
	return ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, caller),
		ContractId: contractId,
		Action:     "transfer",
		Payload:    payload,
		RcLimit:    10000,
		Caller:     caller,
		Intents:    []contracts.Intent{},
	})
}

// ---------------------------------------------------------------------------
// Address format tests for the transfer action
// ---------------------------------------------------------------------------

// TestTransferToHiveAddress verifies transfer to a hive: prefixed address succeeds.
func TestTransferToHiveAddress(t *testing.T) {
	ct, contractId := setupAddrContract(t, 100000)

	r := callTransfer(t, ct, contractId, "hive:testuser", "hive:recipient", "1000")
	if r.Err != "" {
		t.Fatalf("transfer to hive address failed: %s: %s", r.Err, r.ErrMsg)
	}
	assert.True(t, r.Success, "transfer to hive: address should succeed")

	assert.Equal(t, encodeBalance(t, 99000), ct.StateGet(contractId, constants.BalancePrefix+"hive:testuser"))
	assert.Equal(t, encodeBalance(t, 1000), ct.StateGet(contractId, constants.BalancePrefix+"hive:recipient"))
}

// TestTransferToDidKeyAddress verifies transfer to a did:key: address succeeds.
func TestTransferToDidKeyAddress(t *testing.T) {
	ct, contractId := setupAddrContract(t, 100000)

	didKeyAddr := "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	r := callTransfer(t, ct, contractId, "hive:testuser", didKeyAddr, "2000")
	if r.Err != "" {
		t.Fatalf("transfer to did:key address failed: %s: %s", r.Err, r.ErrMsg)
	}
	assert.True(t, r.Success, "transfer to did:key: address should succeed")

	assert.Equal(t, encodeBalance(t, 98000), ct.StateGet(contractId, constants.BalancePrefix+"hive:testuser"))
	assert.Equal(t, encodeBalance(t, 2000), ct.StateGet(contractId, constants.BalancePrefix+didKeyAddr))
}

// TestTransferToDidPkhEip155Address verifies transfer to a did:pkh:eip155 address succeeds.
func TestTransferToDidPkhEip155Address(t *testing.T) {
	ct, contractId := setupAddrContract(t, 100000)

	eip155Addr := "did:pkh:eip155:1:0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18"
	r := callTransfer(t, ct, contractId, "hive:testuser", eip155Addr, "3000")
	if r.Err != "" {
		t.Fatalf("transfer to did:pkh:eip155 address failed: %s: %s", r.Err, r.ErrMsg)
	}
	assert.True(t, r.Success, "transfer to did:pkh:eip155 address should succeed")

	assert.Equal(t, encodeBalance(t, 97000), ct.StateGet(contractId, constants.BalancePrefix+"hive:testuser"))
	assert.Equal(t, encodeBalance(t, 3000), ct.StateGet(contractId, constants.BalancePrefix+eip155Addr))
}

// TestTransferToSystemAddress verifies transfer to a system: address succeeds.
func TestTransferToSystemAddress(t *testing.T) {
	ct, contractId := setupAddrContract(t, 100000)

	systemAddr := "system:treasury"
	r := callTransfer(t, ct, contractId, "hive:testuser", systemAddr, "500")
	if r.Err != "" {
		t.Fatalf("transfer to system address failed: %s: %s", r.Err, r.ErrMsg)
	}
	assert.True(t, r.Success, "transfer to system: address should succeed")

	assert.Equal(t, encodeBalance(t, 99500), ct.StateGet(contractId, constants.BalancePrefix+"hive:testuser"))
	assert.Equal(t, encodeBalance(t, 500), ct.StateGet(contractId, constants.BalancePrefix+systemAddr))
}

// TestTransferToInvalidAddress verifies transfer to an unrecognized address format fails.
func TestTransferToInvalidAddress(t *testing.T) {
	ct, contractId := setupAddrContract(t, 100000)

	r := callTransfer(t, ct, contractId, "hive:testuser", "not-a-valid-address", "1000")
	assert.False(t, r.Success, "transfer to invalid address should fail")
	assert.NotEmpty(t, r.Err)

	// Balance unchanged
	assert.Equal(t, encodeBalance(t, 100000), ct.StateGet(contractId, constants.BalancePrefix+"hive:testuser"))
}

// TestTransferToEmptyAddress verifies transfer to an empty address fails.
func TestTransferToEmptyAddress(t *testing.T) {
	ct, contractId := setupAddrContract(t, 100000)

	r := callTransfer(t, ct, contractId, "hive:testuser", "", "1000")
	assert.False(t, r.Success, "transfer to empty address should fail")
	assert.NotEmpty(t, r.Err)

	// Balance unchanged
	assert.Equal(t, encodeBalance(t, 100000), ct.StateGet(contractId, constants.BalancePrefix+"hive:testuser"))
}

// ---------------------------------------------------------------------------
// Amount validation tests
// ---------------------------------------------------------------------------

// TestTransferZeroAmountFails verifies transfer of zero amount fails.
func TestTransferZeroAmountFails(t *testing.T) {
	ct, contractId := setupAddrContract(t, 100000)

	r := callTransfer(t, ct, contractId, "hive:testuser", "hive:recipient", "0")
	assert.False(t, r.Success, "transfer of zero amount should fail")
	assert.NotEmpty(t, r.Err)

	// Balance unchanged
	assert.Equal(t, encodeBalance(t, 100000), ct.StateGet(contractId, constants.BalancePrefix+"hive:testuser"))
}

// TestTransferNegativeAmountFails verifies transfer of a negative amount fails.
func TestTransferNegativeAmountFails(t *testing.T) {
	ct, contractId := setupAddrContract(t, 100000)

	r := callTransfer(t, ct, contractId, "hive:testuser", "hive:recipient", "-100")
	assert.False(t, r.Success, "transfer of negative amount should fail")
	assert.NotEmpty(t, r.Err)

	// Balance unchanged
	assert.Equal(t, encodeBalance(t, 100000), ct.StateGet(contractId, constants.BalancePrefix+"hive:testuser"))
}

// TestTransferInsufficientBalanceFails verifies transfer exceeding balance fails.
func TestTransferInsufficientBalanceFails(t *testing.T) {
	ct, contractId := setupAddrContract(t, 1000)

	r := callTransfer(t, ct, contractId, "hive:testuser", "hive:recipient", "5000")
	assert.False(t, r.Success, "transfer exceeding balance should fail")
	assert.NotEmpty(t, r.Err)

	// Balance unchanged
	assert.Equal(t, encodeBalance(t, 1000), ct.StateGet(contractId, constants.BalancePrefix+"hive:testuser"))
}

// ---------------------------------------------------------------------------
// Unmap address validation tests (ETH hex address required)
// ---------------------------------------------------------------------------

// TestUnmapValidEthAddress verifies unmap with a valid 0x-prefixed ETH address succeeds.
func TestUnmapValidEthAddress(t *testing.T) {
	ct, contractId := setupAddrContract(t, 100000)

	payload, err := tinyjson.Marshal(mapping.TransferParams{
		To:     "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18",
		Amount: "10000",
	})
	if err != nil {
		t.Fatal(err)
	}
	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, "hive:testuser"),
		ContractId: contractId,
		Action:     "unmap",
		Payload:    payload,
		RcLimit:    10000,
		Caller:     "hive:testuser",
		Intents:    []contracts.Intent{},
	})
	assert.True(t, r.Success, "unmap with valid ETH address should succeed")
	assert.Equal(t, encodeBalance(t, 90000), ct.StateGet(contractId, constants.BalancePrefix+"hive:testuser"))
}

// TestUnmapInvalidEthAddressNoPrefix verifies unmap rejects ETH address without 0x prefix.
func TestUnmapInvalidEthAddressNoPrefix(t *testing.T) {
	ct, contractId := setupAddrContract(t, 100000)

	payload, err := tinyjson.Marshal(mapping.TransferParams{
		To:     "742d35Cc6634C0532925a3b844Bc9e7595f2bD18",
		Amount: "10000",
	})
	if err != nil {
		t.Fatal(err)
	}
	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, "hive:testuser"),
		ContractId: contractId,
		Action:     "unmap",
		Payload:    payload,
		RcLimit:    10000,
		Caller:     "hive:testuser",
		Intents:    []contracts.Intent{},
	})
	assert.False(t, r.Success, "unmap without 0x prefix should fail")
}

// TestUnmapEthAddressTooShort verifies unmap rejects ETH address that is too short.
func TestUnmapEthAddressTooShort(t *testing.T) {
	ct, contractId := setupAddrContract(t, 100000)

	payload, err := tinyjson.Marshal(mapping.TransferParams{
		To:     "0x742d35Cc6634",
		Amount: "10000",
	})
	if err != nil {
		t.Fatal(err)
	}
	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, "hive:testuser"),
		ContractId: contractId,
		Action:     "unmap",
		Payload:    payload,
		RcLimit:    10000,
		Caller:     "hive:testuser",
		Intents:    []contracts.Intent{},
	})
	assert.False(t, r.Success, "unmap with short ETH address should fail")
}

// TestUnmapHiveAddressFails verifies unmap rejects a hive: address (must be ETH format).
func TestUnmapHiveAddressFails(t *testing.T) {
	ct, contractId := setupAddrContract(t, 100000)

	payload, err := tinyjson.Marshal(mapping.TransferParams{
		To:     "hive:recipient",
		Amount: "10000",
	})
	if err != nil {
		t.Fatal(err)
	}
	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, "hive:testuser"),
		ContractId: contractId,
		Action:     "unmap",
		Payload:    payload,
		RcLimit:    10000,
		Caller:     "hive:testuser",
		Intents:    []contracts.Intent{},
	})
	assert.False(t, r.Success, "unmap to hive address should fail (ETH address required)")
}

// TestUnmapEmptyDestinationFails verifies unmap with empty destination fails.
func TestUnmapEmptyDestinationFails(t *testing.T) {
	ct, contractId := setupAddrContract(t, 100000)

	payload, err := tinyjson.Marshal(mapping.TransferParams{
		To:     "",
		Amount: "10000",
	})
	if err != nil {
		t.Fatal(err)
	}
	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, "hive:testuser"),
		ContractId: contractId,
		Action:     "unmap",
		Payload:    payload,
		RcLimit:    10000,
		Caller:     "hive:testuser",
		Intents:    []contracts.Intent{},
	})
	assert.False(t, r.Success, "unmap with empty destination should fail")
}
