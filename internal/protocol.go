// Package yubihsm implements core datatypes and serialization/deserialization
// the YubiHSM2 command protocol.
package yubihsm

import (
	"fmt"
)

//go:generate go run golang.org/x/tools/cmd/stringer -output=protocol_string.go -type=AlgorithmID,CommandID,TypeID

// InvalidLengthError is the error returned when a received YubiHSM2
// message has an invalid length.
type InvalidLengthError struct{}

func (*InvalidLengthError) Error() string {
	return "invalid response length"
}

func badLength() error {
	return &InvalidLengthError{}
}

// ObjectID identifies a key or other object stored on a YubiHSM2.
//
// [YubiHSM2 Object ID]: https://developers.yubico.com/YubiHSM2/Concepts/Object_ID.html
type ObjectID uint16

// AlgorithmID is a cryptographic algorithm identified on a YubiHSM2.
//
// [YubiHSM2 Algorithms]: https://developers.yubico.com/YubiHSM2/Concepts/Algorithms.html
type AlgorithmID uint8

const (
	_ AlgorithmID = iota
	AlgorithmRSAPKCS1SHA1
	AlgorithmRSAPKCS1SHA256
	AlgorithmRSAPKCS1SHA384
	AlgorithmRSAPKCS1SHA512
	AlgorithmRSAPSSSHA1
	AlgorithmRSAPSSSHA256
	AlgorithmRSAPSSSHA384
	AlgorithmRSAPSSSHA512
	AlgorithmRSA2048
	AlgorithmRSA3072
	AlgorithmRSA4096
	AlgorithmECP256
	AlgorithmECP384
	AlgorithmECP521
	AlgorithmECK256
	AlgorithmECBP256
	AlgorithmECBP384
	AlgorithmECBP512
	AlgorithmHMACSHA1
	AlgorithmHMACSHA256
	AlgorithmHMACSHA384
	AlgorithmHMACSHA512
	AlgorithmECDSASHA1
	AlgorithmECECDH
	AlgorithmRSAOAEPSHA1
	AlgorithmRSAOAEPSHA256
	AlgorithmRSAOAEPSHA384
	AlgorithmRSAOAEPSHA512
	AlgorithmAES128CCMWRAP
	AlgorithmOpaqueData
	AlgorithmOpaqueX509Certificate
	AlgorithmMGF1SHA1
	AlgorithmMGF1SHA256
	AlgorithmMGF1SHA384
	AlgorithmMGF1SHA512
	AlgorithmSSHTemplate
	AlgorithmYubicoOTPAES128
	AlgorithmYubicoAESAuthentication
	AlgorithmYubicoOTPAES192
	AlgorithmYubicoOTPAES256
	AlgorithmAES192CCMWRAP
	AlgorithmAES256CCMWRAP
	AlgorithmECDSASHA256
	AlgorithmECDSASHA384
	AlgorithmECDSASHA512
	AlgorithmED25519
	AlgorithmECP224
	AlgorithmRSAPKCSv15Decrypt
	AlgorithmYubicoECP256Authentication
	AlgorithmAES128
	AlgorithmAES192
	AlgorithmAES256
	AlgorithmAESECB
	AlgorithmAESCBC
)

// CommandID is the identified value for a (request, response) message
// pair.
//
// [YubiHSM2 Commands]: https://developers.yubico.com/YubiHSM2/Commands/
type CommandID uint8

const (
	// CommandResponse is the high-order bit which is OR'ed to the
	// command ID in all response messages.
	_, CommandResponse = CommandID(iota), CommandID(0x80 | iota)

	CommandEcho, ResponseEcho
	_, _
	CommandCreateSession, ResponseCreateSession
	CommandAuthenticateSession, ResponseAuthenticateSession
	CommandSessionMessage, ResponseSessionMessage
	CommandGetDeviceInfo, ResponseGetDeviceInfo
	_, _
	CommandResetDevice, ResponseResetDevice
	_, _
	CommandGetDevicePublicKey, ResponseGetDevicePublicKey

	CommandCloseSession = iota + 0x40 - CommandGetDevicePublicKey - 1
	CommandGetStorageInfo
	CommandPutOpaque
	CommandGetOpaque
	CommandPutAuthenticationKey
	CommandPutAsymmetricKey
	CommandGenerateAsymmetricKey
	CommandSignPKCS1v15
	CommandListObjects
	CommandDecryptPKCS1v15
	CommandExportWrapped
	CommandImportWrapped
	CommandPutWrapKey
	CommandGetLogEntries
	CommandGetObjectInfo
	CommandSetOption
	CommandGetOption
	CommandGetPseudoRandom
	CommandPutHMACKey
	CommandSignHMAC
	CommandGetPublicKey
	CommandSignPSS
	CommandSignECDSA
	CommandDeriveECDH
	CommandDeleteObject
	CommandDecryptOAEP
	CommandGenerateHMACKey
	CommandGenerateWrapKey
	CommandVerifyHMAC
	CommandSignSSHCertificate
	CommandPutTemplate
	CommandGetTemplate
	CommandDecryptOTP
	CommandCreateOtpAEAD
	CommandRandomizeOTPAEAD
	CommandRewrapOTPAEAD
	CommandSignAttestationCertificate
	CommandPutOtpAEADKey
	CommandGenerateOTPAEADKey
	CommandSetLogIndex
	CommandWrapData
	CommandUnwrapData
	CommandSignEdDSA
	CommandBlinkDevice
	CommandChangeAuthenticationKey
	CommandPutSymmetricKey
	CommandGenerateSymmetrickey
	CommandDecryptAESECB
	CommandEncryptAESECB
	CommandDecryptAESCBC
	CommandEncryptAEDCBC

	commandError = 0x7f
)

// TypeID is the cryptographic type of an object on the YubiHSM.
//
// [YubiHSM Objects]: https://developers.yubico.com/YubiHSM2/Concepts/Object.html
type TypeID uint8

const (
	TypeOpaque TypeID = iota + 1
	TypeAuthenticationKey
	TypeAsymmetricKey
	TypeWrapKey
	TypeHmacKey
	TypeTemplate
	TypeOtpAeadKey
	TypeSymmetricKey
)

// Error is an error code from the YubiHSM.
//
// [YubiHSM Errors]: https://developers.yubico.com/YubiHSM2/Concepts/Errors.html
type Error uint8

// Error implements [error.Error].
func (e Error) Error() string {
	switch e {
	case 0x00:
		return "success"
	case 0x01:
		return "unknown command"
	case 0x02:
		return "malformed data for the command"
	case 0x03:
		return "the session has expired or does not exist"
	case 0x04:
		return "wrong authentication key"
	case 0x05:
		return "no more available sessions"
	case 0x06:
		return "session setup failed"
	case 0x07:
		return "storage full"
	case 0x08:
		return "wrong data length for the command"
	case 0x09:
		return "insufficient permissions for the command"
	case 0x0a:
		return "the log is full and force audit is enabled"
	case 0x0b:
		return "no object found matching given ID and Type"
	case 0x0c:
		return "invalid ID"
	case 0x0e:
		return "constraints in SSH Template not met"
	case 0x0f:
		return "OTP decryption failed"
	case 0x10:
		return "demo device must be power-cycled"
	case 0x11:
		return "unable to overwrite object"
	default:
		return fmt.Sprintf("yubihsm error(%#x)", int(e))
	}
}

// Command is a serializable message sent to the YubiHSM2.
type Command interface {
	ID() CommandID
	Serialize([]byte) []byte
}

// Response is a deserializable message received from the YubiHSM2.
type Response interface {
	Parse([]byte) error
}

func ParseResponse(cmdID CommandID, rsp Response, buf []byte) error {
	if len(buf) < 3 {
		return fmt.Errorf("response message too short")
	}

	rspCmdID, rspLen := ParseHeader(buf)
	if len(buf)-3 < rspLen {
		return fmt.Errorf("invalid response message length")
	} else if rspCmdID == commandError {
		var e Error
		if rspLen == 1 {
			e = Error(buf[3])
		}
		return fmt.Errorf("received an error response: (%d) %w", e, e)
	} else if rspCmdID != CommandResponse|cmdID {
		return fmt.Errorf("received a response for a different command: %#02x", int(rspCmdID))
	}

	// TODO: check padding?
	// We currently just fuzzily lop the padding off the end.

	return rsp.Parse(buf[3 : 3+rspLen])
}
