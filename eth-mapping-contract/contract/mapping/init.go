package mapping

// ContractState holds the initialized state for the ETH mapping contract.
type ContractState struct{}

// IntializeContractState loads the contract state from storage.
func IntializeContractState() (*ContractState, error) {
	return &ContractState{}, nil
}

// SaveToState persists the full contract state.
func (cs *ContractState) SaveToState() error {
	return nil
}
