package yubihsm

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/pbkdf2"

	yubihsm "github.com/nholstein/yubihsm/internal"
)

// T is either a [testing.T] or [testing.Fuzz].
type T interface {
	Helper()
	Errorf(string, ...any)
	Fatalf(string, ...any)
	Logf(string, ...any)
	Cleanup(func())
}

// testingContext creates a context tied to the deadline of the test.
func testingContext(t T) context.Context {
	deadline := time.Now().Add(time.Second * 10)
	if test, ok := t.(*testing.T); ok {
		if d, ok := test.Deadline(); ok {
			deadline = d
		}
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	t.Cleanup(cancel)
	return ctx
}

// testAuthenticate performs session authentication.
func testAuthenticate(ctx context.Context, t T, conn Connector, s *Session, options ...AuthenticationOption) {
	err := s.Authenticate(ctx, conn, options...)
	if err != nil {
		t.Helper()
		t.Fatalf("session.Authenticate: %v", err)
	}

	t.Logf("authentication completed")
}

// loadReplaySession creates a [Session] using replayed yubihsm-connector
// logs. The returned session is automatically authenticated.
func loadReplaySession(t T, yubihsmConnectorLog string, options ...AuthenticationOption) (context.Context, *replayConnector, *Session) {
	ctx, conn, options := loadReplay(t, yubihsmConnectorLog, options...)
	var session Session
	testAuthenticate(ctx, t, conn, &session, options...)
	return ctx, conn, &session
}

func replayHostChallenge(hostChallenge [8]byte, options ...AuthenticationOption) []AuthenticationOption {
	return append(options, func(c *authConfig) {
		c.rand = bytes.NewReader(hostChallenge[:])
	})
}

func loadReplay(t T, yubihsmConnectorLog string, options ...AuthenticationOption) (context.Context, *replayConnector, []AuthenticationOption) {
	t.Helper()
	ctx := testingContext(t)
	conn := loadReplayConnector(t, yubihsmConnectorLog)
	hostChallenge := conn.findHostChallenge(t)
	return ctx, conn, replayHostChallenge(hostChallenge, options...)
}

func loadMultiReplay(t T, yubihsmConnectorLog string, expect int, options ...AuthenticationOption) (context.Context, Connector, []Session) {
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
		testAuthenticate(ctx, t, conn, &sessions[i], replayHostChallenge(hostChallenge, options...)...)
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

	var session Session
	err := session.Authenticate(context.Background(), nil, func(c *authConfig) {
		c.rand = strings.NewReader("short")
	})
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("expected short read: %v", err)
	}
}

func TestSessionUnauthenticatedSend(t *testing.T) {
	ctx, conn, options := loadReplay(t, "session-open-close.log")
	var session Session

	err := session.Ping(ctx, conn, 0xff)
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("expected %v, got %v", ErrNotAuthenticated, err)
	}

	testAuthenticate(ctx, t, conn, &session, options...)
	testSendPing(ctx, t, conn, &session)
	testSessionClose(ctx, t, conn, &session)
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

	testAuthenticate(ctx, t, conn, &session, replayHostChallenge(hostChallenge)...)

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

// sessionResponse is a [Connector] which responds to commands with the
// encrypted and MACed content of an arbitrary response message.
type sessionResponse struct {
	*Session
	responses [][]byte
}

// SendCommand encrypts and MACs the response message using the current
// key of the [Session].
func (s *sessionResponse) SendCommand(_ context.Context, _ []byte) ([]byte, error) {
	if len(s.responses) == 0 {
		return nil, io.EOF
	}
	response := s.responses[0]
	if len(s.responses) > 1 {
		s.responses = s.responses[1:]
	}

	return s.encryptResponse(response, 0), nil
}

func (s *Session) encryptResponse(response []byte, trim int) []byte {
	out := make([]byte, 4+len(response), 4+15+8+len(response))
	const pad = "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	padding := aes.BlockSize - len(out[4:])%aes.BlockSize
	out = append(out, pad[:padding+macLen]...)

	yubihsm.Put8(out[0:], yubihsm.ResponseSessionMessage)
	yubihsm.Put16(out[1:], len(out)-3)
	yubihsm.Put8(out[3:], s.sessionID)

	inner := out[4 : len(out)-macLen]
	copy(inner, response)

	var iv [aes.BlockSize]byte
	yubihsm.Put32(iv[len(iv)-4:], s.messageCounter-1)
	block, _ := aes.NewCipher(s.encryptionKey[:])
	block.Encrypt(iv[:], iv[:])
	cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(inner, inner)

	inner = inner[:len(inner)-trim]
	out = out[:len(out)-trim]

	mac := s.calculateCMAC(yubihsm.ResponseSessionMessage, s.sessionID, inner)
	copy(out[len(out)-macLen:], mac[:])

	return out
}

func makeSessionResponse(cmd yubihsm.CommandID, msg ...byte) []byte {
	if cmd < 0x7f {
		cmd |= yubihsm.CommandResponse
	}
	return append([]byte{
		byte(cmd),
		byte(len(msg) >> 8),
		byte(len(msg)),
	}, msg...)
}

func loadSessionResponses(t T, responses ...[]byte) (context.Context, Connector, *Session) {
	ctx, _, session := loadReplaySession(t, "session-just-authenticate.log")
	return ctx, &sessionResponse{session, responses}, session
}

func loadSessionResponse(t T, cmd yubihsm.CommandID, msg ...byte) (context.Context, Connector, *Session) {
	return loadSessionResponses(t, makeSessionResponse(cmd, msg...))
}

func TestBadPongData(t *testing.T) {
	ctx, conn, session := loadSessionResponse(t, yubihsm.CommandEcho, 0x0)
	err := session.Ping(ctx, conn, 0xaa)
	if err == nil || err.Error() != "pong response incorrect" {
		t.Errorf("session.Ping(0xaa): %v", err)
	}
}

func TestSessionRekey(t *testing.T) {
	ctx, conn, session := loadSessionResponse(t, yubihsm.CommandEcho, 0xaa)
	t.Logf("session authenticated; this includes one encrypted & authenticated AuthenticateSession command")

	t.Run("send many message", func(t *testing.T) {
		for i := 0; i < maxMessagesBeforeRekey-1; i++ {
			if i%100 == 0 {
				t.Logf("sending %dth session message", i)
			}
			err := session.Ping(ctx, conn, 0xaa)
			if err != nil {
				t.Fatalf("session.Ping(0xaa): %v", err)
			}
		}
		t.Logf("sent %d session messages", maxMessagesBeforeRekey-1)
	})

	t.Run("expect reauthentication", func(t *testing.T) {
		err := session.Ping(ctx, conn, 0xff)
		t.Logf("subsequent messaged received error: %v", err)
		if !errors.Is(err, ErrReauthenticationRequired) {
			t.Errorf("session should have required reauthentication")
		}
	})

	t.Run("reauthenticate", func(t *testing.T) {
		conn := loadReplayConnector(t, "session-open-close.log")
		hostChallenge := conn.findHostChallenge(t)
		testAuthenticate(ctx, t, conn, session, replayHostChallenge(hostChallenge)...)

		t.Log("ping and close should succeed on new session authentication")
		testSendPing(ctx, t, conn, session)
		testSessionClose(ctx, t, conn, session)
	})
}

func FuzzSessionResponseParsing(f *testing.F) {
	for _, seed := range responseCorpus {
		f.Add(seed)
	}

	_, _, authenticated := loadSessionResponse(f, yubihsm.CommandEcho, 0)
	for i := 1; i <= aes.BlockSize; i++ {
		session := authenticated
		f.Add(session.encryptResponse([]byte("Hello, World"), i))
	}

	f.Fuzz(func(t *testing.T, in []byte) {
		session := authenticated
		var iv [aes.BlockSize]byte
		yubihsm.Put32(iv[len(iv)-4:], session.messageCounter)
		block, _ := aes.NewCipher(session.encryptionKey[:])
		block.Encrypt(iv[:], iv[:])

		_, _ = session.decryptSessionResponse(block, iv[:], in)
	})
}

var responseCorpus = [][]byte{
	nil,
	[]byte{0x85, 0, 1, 0},
	[]byte{0x85, 0, 2, 0, 1},
	[]byte{0x85, 0, 3, 0, 1, 2},
	[]byte{0x85, 0, 4, 0, 1, 2, 3},
	[]byte{0x85, 0, 5, 0, 1, 2, 3, 4},
	[]byte{0x85, 0, 6, 0, 1, 2, 3, 4, 5},
	[]byte{0x85, 0, 7, 0, 1, 2, 3, 4, 5, 6},
	[]byte{0x85, 0, 8, 0, 1, 2, 3, 4, 5, 6, 7},
	[]byte{0x85, 0, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8},
	[]byte{0x85, 0, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	[]byte{0x85, 0, 11, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
	[]byte{0x85, 0, 12, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
	[]byte{0x85, 0, 13, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
	[]byte{0x85, 0, 14, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13},
	[]byte{0x85, 0, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},
	[]byte{0x85, 0, 16, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
}
