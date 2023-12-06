package yubihsm

import (
	"testing"
)

func TestPrintBadError(t *testing.T) {
	// Ensure we avoid stack exhaustion.
	var err error = Error(0xff)
	t.Logf("err: %v", err)
}

func TestCommands(t *testing.T) {
	if CommandGetDevicePublicKey != 0x0a {
		t.Errorf("CommandGetDevicePublicKey %x != 0x0a", CommandGetDevicePublicKey)
	}
	if CommandCloseSession != 0x40 {
		t.Errorf("CommandCloseSession %x != 0x40", CommandCloseSession)
	}
	if CommandEncryptAEDCBC != 0x72 {
		t.Errorf("CommandEncryptAEDCBC %x != 0x72", CommandEncryptAEDCBC)
	}
}
