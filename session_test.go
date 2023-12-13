package yubihsm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// testingContext creates a context tied to the deadline of the test.
func testingContext(t *testing.T) context.Context {
	deadline, ok := t.Deadline()
	if !ok {
		deadline = time.Now().Add(time.Second * 10)
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	t.Cleanup(cancel)
	return ctx
}

// testAuthenticate performs session authentication.
func (s *Session) testAuthenticate(ctx context.Context, t *testing.T, conn Connector, options ...AuthenticationOption) {
	err := s.Authenticate(ctx, conn, options...)
	if err != nil {
		t.Helper()
		t.Fatalf("session.Authenticate: %v", err)
	}

	t.Logf("authentication completed")
}

// loadReplaySession creates a [Session] using replayed yubihsm-connector
// logs. The returned session is automatically authenticated.
func loadReplaySession(t *testing.T, yubihsmConnectorLog string, options ...AuthenticationOption) (context.Context, *replayConnector, *Session) {
	ctx, conn, options := loadReplay(t, yubihsmConnectorLog, options...)
	var session Session
	session.testAuthenticate(ctx, t, conn, options...)
	return ctx, conn, &session
}

func loadReplay(t *testing.T, yubihsmConnectorLog string, options ...AuthenticationOption) (context.Context, *replayConnector, []AuthenticationOption) {
	t.Helper()
	ctx := testingContext(t)
	conn := loadReplayConnector(t, yubihsmConnectorLog)
	hostChallenge := conn.findHostChallenge(t)

	return ctx, conn, append(options, func(c *authConfig) {
		c.rand = bytes.NewReader(hostChallenge[:])
	})
}

func loadMultiReplay(t *testing.T, yubihsmConnectorLog string, expect int, options ...AuthenticationOption) (context.Context, Connector, []Session) {
	t.Helper()
	ctx := testingContext(t)

	if false {
		conn := &logMessagesConnector{T: t}
		conn.cleanup(t, yubihsmConnectorLog)

		sessions := make([]Session, expect)
		for i := range sessions {
			session := &sessions[i]
			err := session.Authenticate(ctx, conn)
			if err != nil {
				t.Errorf("sessions[%d].Authenticate(): %v", i, err)
			} else {
				t.Logf("session %d authenticated with SessionID: %d", i, session.sessionID)
			}
		}

		return ctx, conn, sessions
	}

	conn := loadReplayConnector(t, yubihsmConnectorLog)
	hostChallenges := conn.findHostChallenges(t)

	sessions := make([]Session, len(hostChallenges))
	for i, hostChallenge := range hostChallenges {
		sessions[i].testAuthenticate(ctx, t, conn, append(options, func(c *authConfig) {
			c.rand = bytes.NewReader(hostChallenge[:])
		})...)
	}

	if expect >= 0 && expect != len(hostChallenges) {
		t.Fatalf("expected to find %d hostChallenges, but found %d instead", expect, len(hostChallenges))
	}

	return ctx, conn, sessions
}

// testSendPing matches yubihsm-shell's behavior to frequently send an
// Echo(0xff) command. It appears to do this to wake a send loop?
func testSendPing(ctx context.Context, t *testing.T, conn Connector, session *Session) {
	err := session.Ping(ctx, conn, 0xff)
	if err != nil {
		t.Helper()
		t.Errorf("session.Ping(0xff): %v", err)
	}
}

func testSessionClose(ctx context.Context, t *testing.T, conn Connector, session *Session) {
	err := session.Close(ctx, conn)
	if err != nil {
		t.Errorf("session.CloseSession(): %v", err)
	}
}

func TestSessionAuthenticateSession(t *testing.T) {
	ctx, conn, session := loadReplaySession(t, "session-open-close.log")
	testSendPing(ctx, t, conn, session)
	testSessionClose(ctx, t, conn, session)
}

func TestSessionAuthenticationFails(t *testing.T) {
	for log, reason := range map[string]string{
		"session-authenticate-session-fails.log":  "card responds with error",
		"session-bad-create-session-response.log": "authentication with corrupted packets",
		"session-too-many.log":                    "card has too many open sessions",
	} {
		ctx, conn, options := loadReplay(t, log)
		var session Session
		err := session.Authenticate(ctx, conn, options...)
		if err == nil {
			t.Fatalf("authentication should have failed: %s", reason)
		} else {
			t.Logf("authentication failed as desired with error: %v", err)
		}
	}
}

func TestSessionConcurrent(t *testing.T) {
	ctx, conn, sessions := loadMultiReplay(t, "session-concurrent.log", 16)

	t.Logf("generate a slew of traffic")
	ping := make([]byte, 0, 3*len(sessions))
	for i := range sessions {
		// Awkward packet lengths, 3 is mutually prime to the AES
		// block size used for encryption.
		ping = append(ping, byte(i), byte(i), byte(i))

		for j := range sessions[:i+1] {
			session := &sessions[j]
			err := session.Ping(ctx, conn, ping...)
			if err != nil {
				t.Errorf("sessions[%d].Ping(%x): %v", i, ping, err)
			}
		}
	}

	for i := range sessions {
		session := &sessions[i]
		err := session.Close(ctx, conn)
		if err != nil {
			t.Errorf("sessions[%d].Close(): %v", i, err)
		} else {
			t.Logf("session %d closed", i)
		}
	}
}

func TestSessionBadMAC(t *testing.T) {
	ctx, conn, session := loadReplaySession(t, "session-bad-mac.log")
	err := session.Ping(ctx, conn, 0xff)
	if err == nil {
		t.Errorf("response with corrupted MAC should have failed")
	}
}

func TestSessionCustomKeyPassword(t *testing.T) {
	foobar := pbkdf2.Key([]byte("foobar"), []byte("Yubico"), 10_000, 32, sha256.New)
	var encryptionKey, macKey SessionKey
	copy(macKey[:], foobar[copy(encryptionKey[:], foobar):])

	ctx, conn, session := loadReplaySession(t, "password-foobar.log",
		WithAuthenticationKeyID(123),
		WithAuthenticationKeys(encryptionKey, macKey),
	)

	err := session.Ping(ctx, conn, 'b', 'a', 'z')
	if err != nil {
		t.Fatalf("session.Ping: %v", err)
	}
}

func TestSessionGetEd25519PublicKey(t *testing.T) {
	ctx, conn, session := loadReplaySession(t, "get-ed25519-pubkey.log")
	testSendPing(ctx, t, conn, session)

	keyID := ObjectID(0xb37e)
	pubKey, err := session.GetPublicKey(ctx, conn, keyID)
	if err != nil {
		t.Fatalf("session.GetPublicKey(%#x): %v", keyID, err)
	}
	t.Logf("pubKey: %v#", pubKey)
}

func TestSessionGetP256PublicKey(t *testing.T) {
	ctx, conn, session := loadReplaySession(t, "get-p256-pubkey.log")
	testSendPing(ctx, t, conn, session)

	keyID := ObjectID(0xe256)
	pubKey, err := session.GetPublicKey(ctx, conn, keyID)
	if err != nil {
		t.Fatalf("session.GetPublicKey(%#x): %v", keyID, err)
	}
	t.Logf("pubKey: %#v", pubKey)
}

func TestSessionFiveDeviceInfos(t *testing.T) {
	t.Helper()
	ctx := testingContext(t)
	conn := loadReplayConnector(t, "five-device-infos.log")
	hostChallenge := conn.findHostChallenge(t)

	var session Session
	checkDeviceInfo := func(trusted bool) {
		devInfo, err := session.GetDeviceInfo(ctx, conn)
		if err != nil {
			t.Fatalf("session.GetDeviceInfo(): %v", err)
		}
		t.Logf("devInfo: %#v", devInfo)
		if devInfo.Version != "2.0.0" || devInfo.Serial != 123456789 {
			t.Error("incorrect yubihsm.rs mockhsm device info")
		}
		if !devInfo.Trusted && trusted {
			t.Error("device info should be trusted")
		} else if devInfo.Trusted && !trusted {
			t.Error("device info should not be trusted")
		}
	}

	checkDeviceInfo(false)

	session.testAuthenticate(ctx, t, conn, func(c *authConfig) {
		c.rand = bytes.NewReader(hostChallenge[:])
	})

	for i := 0; i < 5; i++ {
		checkDeviceInfo(true)
	}

	_, err := session.GetDeviceInfo(ctx, conn)
	if err == nil {
		t.Errorf("GetDeviceInfo should fail after replaying all messages")
	}
}

func TestSessionLoadKeyPair(t *testing.T) {
	ctx, conn, session := loadReplaySession(t, "load-ed25519-key-by-label.log")
	testSendPing(ctx, t, conn, session)

	keyPair, err := session.LoadKeyPair(ctx, conn, "test-key")
	if err != nil {
		t.Fatalf("session.LoadKeyPair(\"test-key\"): %v", err)
	}

	t.Logf("keyPair: %#v", keyPair)
	if keyPair.keyID != 0xb37e {
		t.Errorf("expected key Object ID 0xb37e, got: %#x", keyPair.keyID)
	}
	public, ok := keyPair.Public().(ed25519.PublicKey)
	if !ok {
		t.Errorf("expected an Ed25519 key pair, got: %T", keyPair.Public())
	} else if !public.Equal(ed25519.PublicKey{0x2d, 0xb2, 0xec, 0xee, 0xa1, 0xb, 0xd8, 0x43, 0xb9, 0xb6, 0x77, 0x3a, 0xcc, 0xa6, 0x90, 0xe3, 0xd3, 0xc5, 0xb7, 0x91, 0x7e, 0x28, 0x1a, 0x3e, 0xe3, 0x85, 0xa4, 0xdb, 0x51, 0x2f, 0x6c, 0x4e}) {
		t.Errorf("incorrect public key")
	}
}
