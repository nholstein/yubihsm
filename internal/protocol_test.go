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

func TestPut(t *testing.T) {
	t.Log("purely to push coverage arbitrarily close to 100%")
	var buf [7]byte
	Put8(buf[0:], 1)
	Put16(buf[1:], 0x0203)
	Put32(buf[3:], 0x04050607)
	expect := "\x01\x02\x03\x04\x05\x06\x07"
	if string(buf[:]) != expect {
		t.Errorf("%q != %q", buf, expect)
	}
}

func TestStrings(t *testing.T) {
	t.Log("purely to push coverage arbitrarily close to 100%")
	for i := 0; i < 256; i++ {
		t.Logf("%v", CommandID(i))
		t.Logf("%v", TypeID(i))
	}
}
