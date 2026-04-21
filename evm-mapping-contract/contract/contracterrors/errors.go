package contracterrors

import (
	"evm-mapping-contract/sdk"
	"errors"
	"strings"
)

type ErrorSymbol string

// Errors
const (
	ErrJson           = ErrorSymbol("json_error")
	ErrStateAccess    = ErrorSymbol("state_access_error")
	ErrAuth           = ErrorSymbol("authentication_error")
	ErrNoPermission   = ErrorSymbol("no_permission")
	ErrInput          = ErrorSymbol("bad_input")
	ErrInvalidHex     = ErrorSymbol("invalid_hex")
	ErrInitialization = ErrorSymbol("contract_not_initialized")
	ErrIntent         = ErrorSymbol("intent_error")
	ErrBalance        = ErrorSymbol("insufficient_balance")
	ErrArithmetic     = ErrorSymbol("overflow_underflow")
	ErrTransaction    = ErrorSymbol("transaction_error")
)

const (
	MsgNoPublicKey = "no registered public key"
	MsgBadInput    = "error unmarshalling input"
)

const (
	errMsgActiveAuth = "active auth required to move funds"
)

type ContractError struct {
	Symbol ErrorSymbol
	Msg    string
}

func (es ErrorSymbol) String() string {
	return string(es)
}

func (e *ContractError) Error() string {
	return e.Symbol.String() + ": " + e.Msg
}

func buildString(prepends []string, msg string) string {
	if len(prepends) == 0 {
		return msg
	}

	var b strings.Builder

	totalLen := len(msg) + (len(prepends) * 2)
	for _, s := range prepends {
		totalLen += len(s)
	}
	b.Grow(totalLen)

	for _, s := range prepends {
		b.WriteString(s)
		b.WriteString(": ")
	}
	b.WriteString(msg)
	return b.String()
}

func NewContractError(symbol ErrorSymbol, msg string, prepends ...string) *ContractError {
	newMsg := buildString(prepends, msg)
	return &ContractError{
		Symbol: symbol,
		Msg:    newMsg,
	}
}

func WrapContractError(symbol ErrorSymbol, err error, prepends ...string) *ContractError {
	var newMsg string
	if err != nil {
		newMsg = buildString(prepends, err.Error())
	}
	return &ContractError{
		Symbol: symbol,
		Msg:    newMsg,
	}
}

func Prepend(err error, prepends ...string) error {
	if len(prepends) == 0 {
		return err
	}

	var origMsg string
	cErr, isCErr := err.(*ContractError)
	if isCErr {
		origMsg = cErr.Msg
	} else {
		origMsg = err.Error()
	}

	newMsg := buildString(prepends, origMsg)
	if isCErr {
		cErr.Msg = newMsg
		return cErr
	} else {
		return errors.New(newMsg)
	}
}

func CustomAbort(err error) {
	if cErr, ok := err.(*ContractError); ok {
		if cErr.Symbol != "" {
			sdk.Revert(cErr.Msg, cErr.Symbol.String())
		} else {
			sdk.Abort(cErr.Msg)
		}
	} else {
		sdk.Abort(err.Error())
	}
}
