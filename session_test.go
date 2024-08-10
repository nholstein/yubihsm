package yubihsm_test

import (
	"context"
	"crypto/aes"
	"crypto/sha256"
	"errors"
	"flag"
	"io"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/pbkdf2"

	"github.com/nholstein/yubihsm"
	internal "github.com/nholstein/yubihsm/internal"
)

var record = flag.Bool("record", false, "enable recording of (mock)HSM messages")

// T is either a [testing.T] or [testing.Fuzz].
type T interface {
	Helper()
	Errorf(msg string, v ...any)
	Fatalf(msg string, v ...any)
	Logf(msg string, v ...any)
	Cleanup(fn func())
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
func testAuthenticate(ctx context.Context, t T, conn yubihsm.Connector, s *yubihsm.Session, options ...yubihsm.AuthenticationOption) {
	err := s.Authenticate(ctx, conn, options...)
	if err != nil {
		t.Helper()
		t.Fatalf("session.Authenticate: %v", err)
	}

	t.Logf("authentication completed")
}

// loadReplaySession creates a [yubihsm.Session] using replayed yubihsm-connector
// logs. The returned session is automatically authenticated.
func loadReplaySession(t T, yubihsmConnectorLog string, options ...yubihsm.AuthenticationOption) (context.Context, testConnector, *yubihsm.Session, []yubihsm.AuthenticationOption) {
	t.Helper()

	if *record {
		ctx := testingContext(t)
		conn := &logMessagesConnector{T: t}
		conn.cleanup(t, yubihsmConnectorLog)

		var session yubihsm.Session
		err := session.Authenticate(ctx, conn, options...)
		if err != nil {
			t.Errorf("sessions.Authenticate(): %v", err)
		} else {
			t.Logf("session authenticated with SessionID: %d", session.SessionID())
		}

		return ctx, conn, &session, options
	}

	ctx, conn, options := loadReplay(t, yubihsmConnectorLog, options...)
	var session yubihsm.Session
	testAuthenticate(ctx, t, conn, &session, options...)
	return ctx, conn, &session, options
}

func loadReplay(t T, yubihsmConnectorLog string, options ...yubihsm.AuthenticationOption) (context.Context, *replayConnector, []yubihsm.AuthenticationOption) {
	t.Helper()
	ctx := testingContext(t)
	conn := loadReplayConnector(t, yubihsmConnectorLog)
	hostChallenges := conn.findHostChallenges(t)
	return ctx, conn, yubihsm.ReplayHostChallenges(hostChallenges, options...)
}

func loadMultiReplay(t T, yubihsmConnectorLog string, expect int, options ...yubihsm.AuthenticationOption) (context.Context, yubihsm.Connector, []yubihsm.Session) {
	t.Helper()
	ctx := testingContext(t)

	if *record {
		conn := &logMessagesConnector{T: t}
		conn.cleanup(t, yubihsmConnectorLog)

		sessions := make([]yubihsm.Session, expect)
		for i := range sessions {
			session := &sessions[i]
			err := session.Authenticate(ctx, conn)
			if err != nil {
				t.Errorf("sessions[%d].Authenticate(): %v", i, err)
			} else {
				t.Logf("session %d authenticated with SessionID: %d", i, session.SessionID())
			}
		}

		return ctx, conn, sessions
	}

	conn := loadReplayConnector(t, yubihsmConnectorLog)
	hostChallenges := conn.findHostChallenges(t)

	sessions := make([]yubihsm.Session, len(hostChallenges))
	for i, hostChallenge := range hostChallenges {
		testAuthenticate(ctx, t, conn, &sessions[i], yubihsm.ReplayHostChallenges([][8]byte{hostChallenge}, options...)...)
	}

	if expect >= 0 && expect != len(hostChallenges) {
		t.Fatalf("expected to find %d hostChallenges, but found %d instead", expect, len(hostChallenges))
	}

	return ctx, conn, sessions
}

// testSendPing matches yubihsm-shell's behavior to frequently send an
// Echo(0xff) command. It appears to do this to wake a send loop?
func testSendPing(ctx context.Context, t *testing.T, conn yubihsm.Connector, session *yubihsm.Session) {
	err := session.Ping(ctx, conn, 0xff)
	if err != nil {
		t.Helper()
		t.Errorf("session.Ping(0xff): %v", err)
	}
}

func testSessionClose(ctx context.Context, t *testing.T, conn yubihsm.Connector, session *yubihsm.Session) {
	err := session.Close(ctx, conn)
	if err != nil {
		t.Errorf("session.CloseSession(): %v", err)
	}
}

func TestSessionAuthenticateSession(t *testing.T) {
	t.Parallel()
	ctx, conn, session, _ := loadReplaySession(t, "session-open-close.log")
	testSendPing(ctx, t, conn, session)
	testSessionClose(ctx, t, conn, session)
}

func TestSessionAuthenticationFails(t *testing.T) {
	t.Parallel()

	for log, reason := range map[string]string{
		"session-authenticate-session-fails.log":  "card responds with error",
		"session-bad-create-session-response.log": "authentication with corrupted packets",
		"session-too-many.log":                    "card has too many open sessions",
	} {
		ctx, conn, options := loadReplay(t, log)
		var session yubihsm.Session
		err := session.Authenticate(ctx, conn, options...)
		if err == nil {
			t.Fatalf("authentication should have failed: %s", reason)
		} else {
			t.Logf("authentication failed as desired with error: %v", err)
		}
	}

	var session yubihsm.Session
	err := session.Authenticate(context.Background(), nil, yubihsm.InvalidRand())
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("expected short read: %v", err)
	}
}

func TestSessionUnauthenticatedSend(t *testing.T) {
	t.Parallel()
	ctx, conn, options := loadReplay(t, "session-open-close.log")
	var session yubihsm.Session

	err := session.Ping(ctx, conn, 0xff)
	if !errors.Is(err, yubihsm.ErrNotAuthenticated) {
		t.Errorf("expected %v, got %v", yubihsm.ErrNotAuthenticated, err)
	}

	testAuthenticate(ctx, t, conn, &session, options...)
	testSendPing(ctx, t, conn, &session)
	testSessionClose(ctx, t, conn, &session)
}

func TestSessionConcurrent(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	ctx, conn, session, _ := loadReplaySession(t, "session-bad-mac.log")
	err := session.Ping(ctx, conn, 0xff)
	if err == nil {
		t.Errorf("response with corrupted MAC should have failed")
	}
}

func TestSessionCustomKeyPassword(t *testing.T) {
	t.Parallel()
	foobar := pbkdf2.Key([]byte("foobar"), []byte("Yubico"), 10_000, 32, sha256.New)
	var encryptionKey, macKey yubihsm.SessionKey
	copy(macKey[:], foobar[copy(encryptionKey[:], foobar):])

	ctx, conn, session, _ := loadReplaySession(t, "password-foobar.log",
		yubihsm.WithAuthenticationKeyID(123),
		yubihsm.WithAuthenticationKeys(encryptionKey, macKey),
	)

	err := session.Ping(ctx, conn, 'b', 'a', 'z')
	if err != nil {
		t.Fatalf("session.Ping: %v", err)
	}
}

func TestSessionGetEd25519PublicKey(t *testing.T) {
	t.Parallel()
	ctx, conn, session, _ := loadReplaySession(t, "get-ed25519-pubkey.log")
	testSendPing(ctx, t, conn, session)

	keyID := yubihsm.ObjectID(0xb37e)
	pubKey, err := session.GetPublicKey(ctx, conn, keyID)
	if err != nil {
		t.Fatalf("session.GetPublicKey(%#x): %v", keyID, err)
	}
	t.Logf("pubKey: %v#", pubKey)
}

func TestSessionGetP256PublicKey(t *testing.T) {
	t.Parallel()
	ctx, conn, session, _ := loadReplaySession(t, "get-p256-pubkey.log")
	testSendPing(ctx, t, conn, session)

	keyID := yubihsm.ObjectID(0xe256)
	pubKey, err := session.GetPublicKey(ctx, conn, keyID)
	if err != nil {
		t.Fatalf("session.GetPublicKey(%#x): %v", keyID, err)
	}
	t.Logf("pubKey: %#v", pubKey)
}

func TestSessionFiveDeviceInfos(t *testing.T) {
	t.Parallel()
	ctx := testingContext(t)
	conn := loadReplayConnector(t, "five-device-infos.log")
	hostChallenges := conn.findHostChallenges(t)

	var session yubihsm.Session
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

	testAuthenticate(ctx, t, conn, &session, yubihsm.ReplayHostChallenges(hostChallenges)...)

	for i := 0; i < 5; i++ {
		checkDeviceInfo(true)
	}

	_, err := session.GetDeviceInfo(ctx, conn)
	if err == nil {
		t.Errorf("GetDeviceInfo should fail after replaying all messages")
	}
}

// sessionResponse is a [yubihsm.Connector] which responds to commands with the
// encrypted and MACed content of an arbitrary response message.
type sessionResponse struct {
	*yubihsm.Session
	responses [][]byte
}

// SendCommand encrypts and MACs the response message using the current
// key of the [yubihsm.Session].
func (s *sessionResponse) SendCommand(_ context.Context, _ []byte) ([]byte, error) {
	if len(s.responses) == 0 {
		return nil, io.EOF
	}
	response := s.responses[0]
	if len(s.responses) > 1 {
		s.responses = s.responses[1:]
	}

	return s.EncryptResponse(response, 0), nil
}

func makeSessionResponse(cmd internal.CommandID, msg ...byte) []byte {
	if cmd < 0x7f {
		cmd |= internal.CommandResponse
	}
	return append([]byte{
		byte(cmd),
		byte(len(msg) >> 8),
		byte(len(msg)),
	}, msg...)
}

func loadSessionResponses(t T, responses ...[]byte) (context.Context, yubihsm.Connector, *yubihsm.Session) {
	ctx, _, session, _ := loadReplaySession(t, "session-just-authenticate.log")
	return ctx, &sessionResponse{session, responses}, session
}

func loadSessionResponse(t T, cmd internal.CommandID, msg ...byte) (context.Context, yubihsm.Connector, *yubihsm.Session) {
	return loadSessionResponses(t, makeSessionResponse(cmd, msg...))
}

func TestBadPongData(t *testing.T) {
	t.Parallel()
	ctx, conn, session := loadSessionResponse(t, internal.CommandEcho, 0x0)
	err := session.Ping(ctx, conn, 0xaa)
	if err == nil || err.Error() != "pong response incorrect" {
		t.Errorf("session.Ping(0xaa): %v", err)
	}
}

func TestSessionRekey(t *testing.T) {
	t.Parallel()
	ctx, conn, session := loadSessionResponse(t, internal.CommandEcho, 0xaa)
	t.Logf("session authenticated; this includes one encrypted & authenticated AuthenticateSession command")

	t.Run("send many message", func(t *testing.T) {
		for i := 0; i < yubihsm.MaxMessagesBeforeRekey-1; i++ {
			if i%100 == 0 {
				t.Logf("sending %dth session message", i)
			}
			err := session.Ping(ctx, conn, 0xaa)
			if err != nil {
				t.Fatalf("session.Ping(0xaa): %v", err)
			}
		}
		t.Logf("sent %d session messages", yubihsm.MaxMessagesBeforeRekey-1)
	})

	t.Run("expect reauthentication", func(t *testing.T) {
		err := session.Ping(ctx, conn, 0xff)
		t.Logf("subsequent messaged received error: %v", err)
		if !errors.Is(err, yubihsm.ErrReauthenticationRequired) {
			t.Errorf("session should have required reauthentication")
		}
	})

	t.Run("reauthenticate", func(t *testing.T) {
		conn := loadReplayConnector(t, "session-open-close.log")
		hostChallenges := conn.findHostChallenges(t)
		testAuthenticate(ctx, t, conn, session, yubihsm.ReplayHostChallenges(hostChallenges)...)

		t.Log("ping and close should succeed on new session authentication")
		testSendPing(ctx, t, conn, session)
		testSessionClose(ctx, t, conn, session)
	})
}

func TestPasswordAuthentication(t *testing.T) {
	withPassword := yubihsm.WithPassword("password")
	ctx, conn, options := loadReplay(t, "session-just-authenticate.log", withPassword)
	var session yubihsm.Session
	testAuthenticate(ctx, t, conn, &session, options...)
}

func TestBadAuthenticationConfig(t *testing.T) {
	withPassword := yubihsm.WithPassword("password")
	ctx, conn, options := loadReplay(t, "session-just-authenticate.log", withPassword)
	var session yubihsm.Session

	err := session.Authenticate(ctx, conn, append(options, yubihsm.WithPassword("foobar"))...)
	if err == nil {
		t.Error("should have rejected setting password multiple times")
	}

	t.Log("confirm authentication otherwise succeeds...")
	testAuthenticate(ctx, t, conn, &session, options...)
}

func TestSessionLocking(t *testing.T) {
	t.Parallel()
	ctx, conn, session, _ := loadReplaySession(t, "session-open-close.log")
	testSendPing(ctx, t, conn, session)
	testSessionClose(ctx, t, conn, session)

	var parallel sync.WaitGroup

	for _, fn := range []func(){
		func() { _ = session.Ping(ctx, conn, 1, 2, 3, 4) },
		func() { _ = session.Close(ctx, conn) },
		func() { _ = session.Authenticate(ctx, conn) },
		func() { _, _ = session.GetPublicKey(ctx, conn, 0x1234) },
		func() { _, _ = session.LoadKeyPair(ctx, conn, "not-a-valid-label") },
		func() { _, _ = session.GetDeviceInfo(ctx, conn) },
	} {
		parallel.Add(1)
		go func() { fn(); parallel.Done() }()
	}

	parallel.Wait()
}

func FuzzSessionResponseParsing(f *testing.F) {
	for _, seed := range responseCorpus {
		f.Add(seed)
	}

	for i := 1; i <= aes.BlockSize; i++ {
		_, _, session := loadSessionResponse(f, internal.CommandEcho, 0)
		f.Add(session.EncryptResponse([]byte("Hello, World"), i))
	}

	_, _, session := loadSessionResponse(f, internal.CommandEcho, 0)
	f.Fuzz(yubihsm.SessionFuzzResponseParsing(session))
}

var responseCorpus = [][]byte{
	nil,
	{0x85, 0, 1, 0},
	{0x85, 0, 2, 0, 1},
	{0x85, 0, 3, 0, 1, 2},
	{0x85, 0, 4, 0, 1, 2, 3},
	{0x85, 0, 5, 0, 1, 2, 3, 4},
	{0x85, 0, 6, 0, 1, 2, 3, 4, 5},
	{0x85, 0, 7, 0, 1, 2, 3, 4, 5, 6},
	{0x85, 0, 8, 0, 1, 2, 3, 4, 5, 6, 7},
	{0x85, 0, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8},
	{0x85, 0, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{0x85, 0, 11, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
	{0x85, 0, 12, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
	{0x85, 0, 13, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
	{0x85, 0, 14, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13},
	{0x85, 0, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},
	{0x85, 0, 16, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
}
