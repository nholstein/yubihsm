package yubihsm

import (
	"bytes"
	"cmp"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"sync"

	"github.com/aead/cmac"
	"golang.org/x/crypto/pbkdf2"

	yubihsm "github.com/nholstein/yubihsm/internal"
)

const (
	// The length of the keys used for AES encryption and MACs.
	sessionKeyLen = 16

	// The length of the MAC field in a message.
	macLength = 8

	// The maximum number of encrypted messages to send in a session
	// before rekeying.
	maxMessagesBeforeRekey = 10_000

	pbkdfIterations           = 10_000
	defaultAuthKeyID ObjectID = 1

	// sessionHeaderLength is command ID, length, session ID.
	sessionHeaderLength = 1 + 2 + 1

	deriveEncKey  = 4
	deriveMacKey  = 6
	deriveRmacKey = 7
)

// ObjectID identifies a key or other object stored on a YubiHSM2.
//
// [YubiHSM2 Object ID]: https://developers.yubico.com/YubiHSM2/Concepts/Object_ID.html
type ObjectID = yubihsm.ObjectID

// SessionKey is a random key used to authenticate and encrypt a
// YubiHSM2 session.
//
// These should always be randomly generated.
type SessionKey [sessionKeyLen]byte

type sessionError string

func (s sessionError) Error() string {
	return string(s)
}

const (
	// ErrNotAuthenticated is returned if a command is sent over an
	// unauthenticated [Session].
	ErrNotAuthenticated sessionError = "cannot send message over unauthenticated session"

	// ErrReauthenticationRequired is returned when the maximum number
	// of commands have been sent over an encrypted [Session]. The
	// session must be reauthenticated by calling [Session.Authenticate].
	ErrReauthenticationRequired sessionError = "maximum messages sent; session must reauthenticate"

	// ErrIncorrectMAC is returned when a response from the YubiHSM2
	// has an inccorect MAC.
	ErrIncorrectMAC sessionError = "session message MAC failed"

	// ErrInvalidMessage is returned when a response message cannot
	// be processed; generally indicating the length is incorrect.
	ErrInvalidMessage sessionError = "invalid response message"
)

// AuthenticationOption configures an HSM [Session].
type AuthenticationOption func(*Session, *authConfig) error

type authConfig struct {
	rand    io.Reader
	keyID   ObjectID
	encKey  SessionKey
	macKey  SessionKey
	hasKeys bool
}

func (c *authConfig) authKeys() (SessionKey, SessionKey) {
	if c.hasKeys {
		return c.encKey, c.macKey
	}

	// The default encryption and MAC key, derived from "password".
	// See [TestGenerateDefaultKey] for details.
	return SessionKey{0x9, 0xb, 0x47, 0xdb, 0xed, 0x59, 0x56, 0x54, 0x90, 0x1d, 0xee, 0x1c, 0xc6, 0x55, 0xe4, 0x20},
		SessionKey{0x59, 0x2f, 0xd4, 0x83, 0xf7, 0x59, 0xe2, 0x99, 0x9, 0xa0, 0x4c, 0x45, 0x5, 0xd2, 0xce, 0xa}
}

func (c *authConfig) apply(s *Session, options []AuthenticationOption) error {
	var err error
	for _, option := range options {
		err = errors.Join(err, option(s, c))
	}
	return err
}

func deriveAuthenticationKeys(password string) (encryptionKey, macKey SessionKey) {
	l := len(encryptionKey) + len(macKey)
	key := pbkdf2.Key([]byte(password), []byte("Yubico"), pbkdfIterations, l, sha256.New)
	l = copy(encryptionKey[:], key)
	copy(macKey[:], key[l:])
	return
}

// WithAuthenticationKeys sets the authentication key of a session. If
// left unspecified the session uses keys derived from the default HSM
// password.
//
// At most one of [WithPassword] or [WithAuthenticationKeys] may be used.
func WithAuthenticationKeys(encryptionKey, macKey SessionKey) AuthenticationOption {
	return func(_ *Session, c *authConfig) error {
		if c.hasKeys {
			return Error("authentication keys/password specified multiple times")
		}

		c.encKey = encryptionKey
		c.macKey = macKey
		c.hasKeys = true
		return nil
	}
}

// WithPassword sets the authentication password of a session. If left
// unspecified the session uses the default HSM password.
//
// At most one of [WithPassword] or [WithAuthenticationKeys] may be used.
func WithPassword(password string) AuthenticationOption {
	return WithAuthenticationKeys(deriveAuthenticationKeys(password))
}

// WithAuthenticationKeyID sets the authentication key ID of a session.
// If left unspecified the default HSM ID 1 is used.
func WithAuthenticationKeyID(keyID ObjectID) AuthenticationOption {
	return func(_ *Session, c *authConfig) error {
		c.keyID = keyID
		return nil
	}
}

// Session is an encrypted and authenticated communication channel to an
// HSM. It can be used to exchange commands and responses to the HSM.
//
// The zero Session is valid to use.
//
//	var session Session
//	err := session.Authenticate(ctx, conn)
//
// [YubiHSM2 Session]: https://developers.yubico.com/YubiHSM2/Concepts/Session.html
type Session struct {
	lock sync.Mutex
	session
}

// session holds the cryptographic state of a [Session]. Access to its
// fields must be synchronized to avoid races.
type session struct {
	encryptionKey  SessionKey
	macKey         SessionKey
	rmacKey        SessionKey
	macChaining    SessionKey
	messageCounter uint32
	sessionID      byte
}

// createSession generates a [Create Session command] message.
//
// [Create Session command]: https://developers.yubico.com/YubiHSM2/Commands/Create_Session.html
func (c *authConfig) createSession() (yubihsm.CreateSessionCommand, error) {
	cmd := yubihsm.CreateSessionCommand{
		KeySetID: cmp.Or(c.keyID, defaultAuthKeyID),
	}
	_, err := io.ReadFull(cmp.Or(c.rand, rand.Reader), cmd.HostChallenge[:])
	return cmd, err
}

func deriveKey(lenDerived, derivationConstant byte, key SessionKey, hostChallenge, deviceChallenge yubihsm.Challenge) (derived SessionKey) {
	// SCP0 §4.1.5 Data Derivation Scheme
	fixedInput := [16]byte{
		// A 12-byte “label” consisting of 11 bytes with value
		// '00' followed by a 1-byte derivation constant
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, derivationConstant,
		// A 1-byte “separation indicator” with value '00'.
		0,
		// A 2-byte integer “L” specifying the length in bits
		// of the derived data
		0, 8 * lenDerived,
		// A 1-byte counter “i” as specified in the KDF
		1,
	}

	// Keys are hardcoded to 16 bytes; cipher and CMAC construction
	// cannot fail.
	block, _ := aes.NewCipher(key[:])
	mac, _ := cmac.New(block)

	_, _ = mac.Write(fixedInput[:])
	_, _ = mac.Write(hostChallenge[:])
	_, _ = mac.Write(deviceChallenge[:])

	// CMAC produces 16 bytes so hash directly into the returned key.
	mac.Sum(derived[:0])
	return derived
}

func deriveSessionKey(derivationConstant byte, key SessionKey, hostChallenge, deviceChallenge yubihsm.Challenge) SessionKey {
	return deriveKey(sessionKeyLen, derivationConstant, key, hostChallenge, deviceChallenge)
}

func deriveCryptogram(derivationConstant byte, key SessionKey, hostChallenge, deviceChallenge yubihsm.Challenge) (derived yubihsm.Cryptogram) {
	key = deriveKey(byte(len(derived)), derivationConstant, key, hostChallenge, deviceChallenge)
	copy(derived[:], key[:])
	return derived
}

// authenticateSession processes the create-session response and creates
// an authenticate-session command. The various session authentication
// keys and cryptograms are updated with the derived values computed from
// the exchange.
//
// https://developers.yubico.com/YubiHSM2/Commands/Create_Session.html
// https://developers.yubico.com/YubiHSM2/Commands/Authenticate_Session.html
func (s *session) authenticateSession(encKey, macKey SessionKey, hostChallenge yubihsm.Challenge, create *yubihsm.CreateSessionResponse) (*yubihsm.AuthenticateSessionCommand, error) {
	rmacKey := deriveSessionKey(deriveRmacKey, macKey, hostChallenge, create.CardChallenge)
	macKey = deriveSessionKey(deriveMacKey, macKey, hostChallenge, create.CardChallenge)
	encKey = deriveSessionKey(deriveEncKey, encKey, hostChallenge, create.CardChallenge)

	cardCryptogram := deriveCryptogram(0, macKey, hostChallenge, create.CardChallenge)
	if subtle.ConstantTimeCompare(cardCryptogram[:], create.CardCryptogram[:]) != 1 {
		return nil, Error("card cryptogram MAC incorrect")
	}

	s.encryptionKey = encKey
	s.macKey = macKey
	s.rmacKey = rmacKey
	s.sessionID = create.SessionID
	s.messageCounter = 1

	cmd := yubihsm.AuthenticateSessionCommand{
		SessionID: create.SessionID,
	}
	cmd.HostCryptogram = deriveCryptogram(1, macKey, hostChallenge, create.CardChallenge)
	s.macChaining = calculateCMAC(s.macKey, s.macChaining, cmd.ID(), cmd.SessionID, cmd.HostCryptogram[:])
	copy(cmd.CMAC[:], s.macChaining[:])

	return &cmd, nil
}

// Authenticate performs the cryptographic exchange to authenticate with
// the YubiHSM2 and establish an encrypted communication channel.
func (s *Session) Authenticate(ctx context.Context, conn Connector, options ...AuthenticationOption) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	// TODO: close the existing session?
	// TODO: perform work in a temporary, without lock held.

	// Clear out all keys when beginning authentication.
	s.session = session{}

	var config authConfig
	err := config.apply(s, options)
	if err != nil {
		return err
	}

	createSessionCmd, err := config.createSession()
	if err != nil {
		return err
	}

	var createSessionRsp yubihsm.CreateSessionResponse
	err = sendPlaintext(ctx, conn, &createSessionCmd, &createSessionRsp)
	if err != nil {
		return err
	}

	encKey, macKey := config.authKeys()
	authenticateSessionCmd, err := s.authenticateSession(encKey, macKey, createSessionCmd.HostChallenge, &createSessionRsp)
	if err != nil {
		return err
	}

	var authenticateSessionRsp yubihsm.AuthenticateSessionResponse
	return sendPlaintext(ctx, conn, authenticateSessionCmd, &authenticateSessionRsp)
}

// GetDeviceInfo retrieves the HSM's status information.
//
// This is the only command other than [Session.Authenticate] which can
// be called on an unauthenticated session, and the only command which
// can be called on either an authenticated _or_ unauthenticated session.
//
// If the session isn't authenticated then the returned device information
// itself is neither encrypted not authenticated. It therefore should not
// be trusted; but this can be useful sometimes to e.g. lookup an HSM's
// configuration by its serial number prior to establishing a session.
//
// If untrusted device information is used then it should be confirmed
// after authenticating the session by requesting the device info again
// and confirming against trusted values:
//
//	var session Session
//	untrustedDevInfo, _ := session.GetDeviceInfo(ctx, conn)
//	authKey, _ := keys[untrustedDevInfo.Serial]
//	_ = session.Authenticate(ctx, conn, WithAuthenticationKeys(authKey))
//	trustedDevInfo, _ := session.GetDeviceInfo(ctx, conn)
//	if trustedDevInfo.Serial != untrustedDevInfo.Serial {
//		println("Lies!")
//	}
func (s *Session) GetDeviceInfo(ctx context.Context, conn Connector) (DeviceInfo, error) {
	var (
		cmd yubihsm.DeviceInfoCommand
		rsp yubihsm.DeviceInfoResponse
	)

	// sendCommand checks the authentication state as its first step
	// after locking the session. Fallback to an unencrypted request
	// if the session isn't authenticated.

	trusted := true
	err := s.sendCommand(ctx, conn, false, cmd, &rsp)
	if errors.Is(err, ErrNotAuthenticated) {
		trusted = false
		err = sendPlaintext(ctx, conn, cmd, &rsp)
	}
	if err != nil {
		return DeviceInfo{}, err
	}

	return DeviceInfo{
		Version:    rsp.Version,
		Serial:     rsp.Serial,
		LogStore:   rsp.LogStore,
		LogLines:   rsp.LogLines,
		Algorithms: rsp.Algorithms,
		Trusted:    trusted,
	}, nil
}

// Close cleanly shuts the session down. A closed [Session] cannot be
// reused. After closing a session any [KeyPair]s loaded will no longer
// work.
//
// This does not implement the standard [io.Closer] interface since a
// [context.Context] and [Connector] must be provided to send a close
// message to the HSM.
func (s *Session) Close(ctx context.Context, conn Connector) error {
	// Reset the messageCounter within encryptCommand to mark the
	// session as unauthenticated.
	return s.sendCommand(ctx, conn, true, yubihsm.CloseSessionCommand{}, yubihsm.CloseSessionResponse{})
}

// Ping sends a [ping] message to the YubiHSM2 and returns the received
// [pong] response. It uses the [Echo command] to send and receive data.
//
// The most common use of the echo command is to implement a session
// keepalive heartbeat; to mimic the yubihsm-shell's behavior use:
//
//	err = session.Ping(ctx, conn, 0xff)
//
// [Echo command]: https://developers.yubico.com/YubiHSM2/Commands/Echo.html
func (s *Session) Ping(ctx context.Context, conn Connector, data ...byte) error {
	pingPong := yubihsm.Echo(data)
	err := s.sendCommand(ctx, conn, false, pingPong, &pingPong)
	if err != nil {
		return err
	} else if !bytes.Equal(data, pingPong) {
		return Error("pong response incorrect")
	}

	return nil
}

// getPublicKey retrieves the public half of an asymmetric keypair in
// the HSM.
//
// The return public key will be one of an [*ecdsa.PublicKey],
// [ed25519.PublicKey], or an [*rsa.PublicKey].
func (s *Session) getPublicKey(ctx context.Context, conn Connector, keyID ObjectID) (yubihsm.PublicKey, error) { //nolint:ireturn
	cmd := yubihsm.GetPublicKeyCommand{
		KeyID: keyID,
	}
	var rsp yubihsm.GetPublicKeyResponse
	err := s.sendCommand(ctx, conn, false, &cmd, &rsp)
	if err != nil {
		return nil, err
	}
	return rsp.PublicKey, nil
}

// LoadKeyPair looks up the asymmetric keypair in the HSM using the
// provided [label] and returns a [KeyPair] which can be used to sign
// messages or decrypt ciphertext.
//
// The returned key's public will be one of an [*ecdsa.PublicKey],
// [ed25519.PublicKey], or an [*rsa.PublicKey]. Dependent upon the key's
// type and the [Effective Capabilities] [KeyPair.Sign] and/or
// [KeyPair.Decrypt] will work.
//
// [Effective Capabilities]: https://developers.yubico.com/YubiHSM2/Concepts/Effective_Capabilities.html
func (s *Session) LoadKeyPair(ctx context.Context, conn Connector, label string) (*KeyPair, error) {
	cmd := yubihsm.ListObjectsCommand{
		yubihsm.TypeFilter(yubihsm.TypeAsymmetricKey),
		yubihsm.LabelFilter(label),
	}
	var rsp yubihsm.ListObjectsResponse
	err := s.sendCommand(ctx, conn, false, cmd, &rsp)
	switch {
	case err != nil:
		return nil, err

	case len(rsp) == 0:
		return nil, yubihsm.Errorf("could not find asymmetric-key labeled %q", label)

	case len(rsp) > 1:
		// This should be impossible, keys are identified via
		// the (type, ID) pair.
		return nil, yubihsm.Errorf("HSM error: found %d asymmetric-keys labeled %q", len(rsp), label)
	}

	keyID := rsp[0].Object
	public, err := s.getPublicKey(ctx, conn, keyID)
	if err != nil {
		return nil, err
	}

	return &KeyPair{public, keyID}, nil
}

func calculateCMAC(key, chaining SessionKey, cmd yubihsm.CommandID, session byte, contents []byte) (k SessionKey) {
	// Keys are hardcoded to 16 bytes; cipher and CMAC construction
	// cannot fail.
	block, _ := aes.NewCipher(key[:])
	mac, _ := cmac.New(block)

	// Compute the CMAC over the chaining MAC, the message header,
	// and its contents.
	l := 1 + macLength + len(contents)
	header := [4]byte{byte(cmd), byte(l >> 8), byte(l), session} //nolint:mnd
	_, _ = mac.Write(chaining[:])
	_, _ = mac.Write(header[:])
	_, _ = mac.Write(contents)

	// CMAC produces 16 bytes so hash directly into the returned key.
	mac.Sum(k[:0])
	return
}

// sendCommand encrypts a session message command, transmits it via the
// provided connector, and then decrypts the response.
//
// It must be called with the session unlocked.
func (s *Session) sendCommand(ctx context.Context, conn Connector, reset bool, cmd yubihsm.Command, rsp yubihsm.Response) error {
	// While the largest command supported is ~2kB, this should be
	// large enough for the majority of commands sent without causing
	// too much heap spillage.
	var buf [256]byte

	// Encrypt the command, return the encrypted command an the
	// decryption state. This step locks the session.
	decrypt, message, err := s.encryptCommand(cmd, buf[:0], reset)
	if err != nil {
		return err
	}

	// After this point the session is unlocked, and the variable
	// itself cannot be used to validate the incoming response.

	// Send the command, and verify the session message response
	// envelope.
	message, err = conn.SendCommand(ctx, message)
	if err != nil {
		return err
	}

	message, err = decrypt.decryptSessionResponse(message)
	if err != nil {
		return err
	}

	// Validate the inner message header correctness.
	return yubihsm.ParseResponse(cmd.ID(), rsp, message)
}

func (s *Session) encryptCommand(cmd yubihsm.Command, buf []byte, reset bool) (*decryptResponse, []byte, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.messageCounter == 0 {
		return nil, nil, ErrNotAuthenticated
	} else if s.messageCounter >= maxMessagesBeforeRekey {
		return nil, nil, ErrReauthenticationRequired
	}

	// We serialize and encrypt the command message in-place within a
	// session message envelope. The overhead consists of the 4-byte
	// header and trailer of padding and 8-byte MAC.
	//
	// TODO: potential memory optimization: preallocate extra space
	// for padding and MAC in the front of [buf]. If there's no room
	// after [message] in [buf] then memmove to the front of [buf]
	// and append the padding and MAC. This would avoid a potential
	// double allocation of the message for long commands.
	message := cmd.Serialize(buf[:sessionHeaderLength])

	// Pad the inner message to a multiple of the AES block size.
	// Padding consists of a single 0x80 byte followed by zeroes.
	//
	// To optimize memory usage, additionally reserve space for the
	// appended MAC.
	const pad = "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	padding := aes.BlockSize - len(message[sessionHeaderLength:])%aes.BlockSize
	message = append(message, pad[:padding+macLength]...)

	// Construct the session message header in-place. This must be
	// done after inner message serialization and padding because
	// the total length must be known.
	yubihsm.Put8(message[0:], yubihsm.CommandSessionMessage)
	yubihsm.Put16(message[1:], len(message)-yubihsm.HeaderLength)
	yubihsm.Put8(message[3:], s.sessionID)

	// Encrypt the session message and insert the CMAC.
	block, iv := s.encryptThenMAC(message)

	// Reset the messageCounter when closing a session, otherwise
	// increment the counter .
	if reset {
		s.messageCounter = 0
	} else {
		s.messageCounter++
	}

	return &decryptResponse{s.rmacKey, s.macChaining, block, iv, s.sessionID}, message, nil
}

// encryptThenMAC encrypts the message in-place then computes the message
// CMAC and writes it in the final 8 bytes of the message. Space for the
// header and MAC must be allocated at the front and back.
//
// Returns the AES block cipher and IV which can be used to decrypt the
// response.
func (s *session) encryptThenMAC(message []byte) (cipher.Block, []byte) {
	// Create the CBC IV: 16 bytes; 12 zeroes and 32-bit counter. The
	// serialized counter is encrypted with the session encryption
	// key to result in the IV.
	var iv [aes.BlockSize]byte
	yubihsm.Put32(iv[len(iv)-4:], s.messageCounter)

	block, _ := aes.NewCipher(s.encryptionKey[:])
	block.Encrypt(iv[:], iv[:])

	// Encrypt the serialized and padded inner message.
	inner := message[sessionHeaderLength : len(message)-macLength]
	cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(inner, inner)

	// The appended MAC is the first 8 bytes of the truncated session
	// chaining MAC.
	s.macChaining = calculateCMAC(s.macKey, s.macChaining, yubihsm.CommandSessionMessage, s.sessionID, inner)
	copy(message[len(message)-macLength:], s.macChaining[:macLength])

	return block, iv[:]
}

// decryptResponse holds the session state needed to decrypt a response
// message from the HSM. Each instance is valid for a single invocation
// of [Session.sendCommand] and should not be reused.
type decryptResponse struct {
	rmacKey     SessionKey
	macChaining SessionKey
	block       cipher.Block
	iv          []byte
	sessionID   byte
}

// decryptSessionResponse decrypts a response message from the YubiHSM2
// and returns the inner message. The message is decrypted in-place, so
// the returned plaintext message aliases the incoming message buffer.
func (d *decryptResponse) decryptSessionResponse(message []byte) ([]byte, error) {
	if len(message) < sessionHeaderLength+yubihsm.HeaderLength+macLength {
		// Four bytes in outer session message, three bytes inner,
		// eight bytes of MAC.
		return nil, ErrInvalidMessage
	} else if len(message)%aes.BlockSize != sessionHeaderLength+macLength {
		// Padding of the inner message is incorrect.
		return nil, ErrInvalidMessage
	}

	msgCmdID, msgLen := yubihsm.ParseHeader(message)
	switch {
	case msgCmdID != yubihsm.ResponseSessionMessage:
		return nil, ErrInvalidMessage

	case msgLen != len(message)-yubihsm.HeaderLength:
		return nil, ErrInvalidMessage

	case message[yubihsm.HeaderLength] != d.sessionID:
		return nil, yubihsm.Errorf("session %d received response for session %d", d.sessionID, message[3])
	}

	// Verify the response MAC by comparing it to the expected value.
	inner := message[sessionHeaderLength : len(message)-macLength]
	validMAC := calculateCMAC(d.rmacKey, d.macChaining, yubihsm.ResponseSessionMessage, d.sessionID, inner)
	recvedMAC := message[len(message)-macLength:]
	if subtle.ConstantTimeCompare(validMAC[:macLength], recvedMAC) != 1 {
		return nil, ErrIncorrectMAC
	}

	// Decrypt the inner response message.
	cipher.NewCBCDecrypter(d.block, d.iv).CryptBlocks(inner, inner)
	return inner, nil
}
