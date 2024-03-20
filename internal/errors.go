package yubihsm

import (
	"fmt"
)

const (
	errInvalidECDSA         = LogicError("invalid ECDSA public key")
	errInvalidEd25519       = LogicError("invalid Ed25519 public key")
	errInvalidLength        = LogicError("invalid response length")
	errInvalidPadding       = LogicError("invalid response CBC padding")
	errInvalidRSA           = LogicError("invalid RSA public key")
	errShortResponse        = LogicError("response message too short")
	errTrailingBytes        = LogicError("trailing bytes in response")
	errUnsupportedAlgorithm = LogicError("unsupported algorithm")
)

// LogicError is the error type for a protocol error arising from an
// invalid response from a YubiHSM2.
type LogicError string

// Error implements [error.Error].
func (e LogicError) Error() string {
	return string(e)
}

func Errorf(msg string, v ...any) LogicError {
	return LogicError(fmt.Sprintf(msg, v...))
}
