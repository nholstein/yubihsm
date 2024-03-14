package yubihsm_test

import (
	"testing"

	yubihsm "github.com/nholstein/yubihsm/internal"
)

func TestPrintBadError(t *testing.T) {
	// Ensure we avoid stack exhaustion.
	var err error = yubihsm.Error(0xff)
	t.Logf("err: %v", err)
}

func TestCommands(t *testing.T) {
	if yubihsm.CommandGetDevicePublicKey != 0x0a {
		t.Errorf("CommandGetDevicePublicKey %x != 0x0a", yubihsm.CommandGetDevicePublicKey)
	}
	if yubihsm.CommandCloseSession != 0x40 {
		t.Errorf("CommandCloseSession %x != 0x40", yubihsm.CommandCloseSession)
	}
	if yubihsm.CommandEncryptAEDCBC != 0x72 {
		t.Errorf("CommandEncryptAEDCBC %x != 0x72", yubihsm.CommandEncryptAEDCBC)
	}
}

func TestPut(t *testing.T) {
	t.Log("purely to push coverage arbitrarily close to 100%")
	var buf [7]byte
	yubihsm.Put8(buf[0:], 1)
	yubihsm.Put16(buf[1:], 0x0203)
	yubihsm.Put32(buf[3:], 0x04050607)
	expect := "\x01\x02\x03\x04\x05\x06\x07"
	if string(buf[:]) != expect {
		t.Errorf("%q != %q", buf, expect)
	}
}

func TestStrings(t *testing.T) {
	t.Log("purely to push coverage arbitrarily close to 100%")
	for i := 0; i < 256; i++ {
		t.Logf("%v", yubihsm.CommandID(i))
		t.Logf("%v", yubihsm.TypeID(i))
	}
}

func TestErrors(t *testing.T) {
	if yubihsm.ErrSuccess != 0 {
		t.Errorf("success != 0")
	}
	if yubihsm.ErrUnableToOverwrite != 0x11 {
		t.Errorf("ErrUnableToOverwrite != 0x11: %d", yubihsm.ErrUnableToOverwrite)
	}
}
