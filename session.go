package yubihsm

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"github.com/aead/cmac"

	yubihsm "github.com/nholstein/yubihsm/internal"
)

// Run to rederive the default authentication key. This value will never
// change, so you shouldn't ever need to run this.
//go:generate go test github.com/nholstein/yubihsm -generate-default-key

const (
	// The length of the keys used for AES encryption and MACs.
	sessionKeyLen = 16

	// The length of the MAC field in a message
	macLength = 8

	// The maximum number of encrypted messages to send in a session
	// before rekeying.
	maxMessagesBeforeRekey = 10_000

	defaultAuthKeyID ObjectID = 1

	// command ID (0x05/0x85), length, session ID
	sessionHeaderLength = 1 + 2 + 1
)

// ObjectID identifies a key or other object stored on a YubiHSM2.
//
// [YubiHSM2 Object ID]: https://developers.yubico.com/YubiHSM2/Concepts/Object_ID.html
type ObjectID = yubihsm.ObjectID

// SessionKey is a random key key used to authenticate and encrypt a
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
type AuthenticationOption func(*authConfig)

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
	return defaultEncryptionKey(), defaultMACKey()
}

func (c *authConfig) apply(options []AuthenticationOption) {
	for _, option := range options {
		option(c)
	}
}

// WithAuthenticationKeys sets the authentication key of a session. If
// left unspecified the session uses keys derived from the default HSM
// password.
func WithAuthenticationKeys(encryptionKey, macKey SessionKey) AuthenticationOption {
	return func(c *authConfig) {
		c.encKey = encryptionKey
		c.macKey = macKey
		c.hasKeys = true
	}
}

// WithAuthenticationKeyID sets the authentication key ID of a session.
// If left unspecified the default HSM ID 1 is used.
func WithAuthenticationKeyID(keyID ObjectID) AuthenticationOption {
	return func(c *authConfig) {
		c.keyID = keyID
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
		KeySetID: orDefault(c.keyID, defaultAuthKeyID),
	}
	_, err := io.ReadFull(orDefault(c.rand, rand.Reader), cmd.HostChallenge[:])
	return cmd, err
}

func deriveKey(len, derivationConstant byte, key SessionKey, hostChallenge, deviceChallenge yubihsm.Challenge) (derived SessionKey) {
	// SCP0 §4.1.5 Data Derivation Scheme
	fixedInput := [16]byte{
		// A 12-byte “label” consisting of 11 bytes with value
		// '00' followed by a 1-byte derivation constant
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, derivationConstant,
		// A 1-byte “separation indicator” with value '00'.
		0,
		// A 2-byte integer “L” specifying the length in bits
		// of the derived data
		0, 8 * len,
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
func (s *Session) authenticateSession(encKey, macKey SessionKey, hostChallenge yubihsm.Challenge, create *yubihsm.CreateSessionResponse) (*yubihsm.AuthenticateSessionCommand, error) {
	rmacKey := deriveSessionKey(7, macKey, hostChallenge, create.CardChallenge)
	macKey = deriveSessionKey(6, macKey, hostChallenge, create.CardChallenge)
	encKey = deriveSessionKey(4, encKey, hostChallenge, create.CardChallenge)

	cardCryptogram := deriveCryptogram(0, macKey, hostChallenge, create.CardChallenge)
	if subtle.ConstantTimeCompare(cardCryptogram[:], create.CardCryptogram[:]) != 1 {
		return nil, fmt.Errorf("card cryptogram MAC incorrect")
	}

	s.encryptionKey = encKey
	s.macKey = macKey
	s.rmacKey = rmacKey
	s.sessionID = create.SessionID
	s.messageCounter = 1

	rsp := yubihsm.AuthenticateSessionCommand{
		SessionID: create.SessionID,
	}
	rsp.HostCryptogram = deriveCryptogram(1, macKey, hostChallenge, create.CardChallenge)
	s.macChaining = s.calculateCMAC(rsp.ID(), rsp.SessionID, rsp.HostCryptogram[:])
	copy(rsp.CMAC[:], s.macChaining[:])

	return &rsp, nil
}

// Authenticate performs the cryptographic exchange to authenticate with
// the YubiHSM2 and establish an encrypted communication channel.
func (s *Session) Authenticate(ctx context.Context, conn Connector, options ...AuthenticationOption) error {
	// Clear out all keys when beginning authentication.
	*s = Session{}

	var config authConfig
	config.apply(options)

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
		buf []byte
		err error
	)

	// messageCounter is set to 1 after establishing a session (and
	// set to 0 on close).
	trusted := s.messageCounter > 0

	if trusted {
		err = s.sendCommand(ctx, conn, cmd, &rsp)
	} else {
		buf, err = conn.SendCommand(ctx, cmd.Serialize(nil))
		if err == nil {
			err = yubihsm.ParseResponse(cmd.ID(), &rsp, buf)
		}
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
	err := s.sendCommand(ctx, conn, yubihsm.CloseSessionCommand{}, yubihsm.CloseSessionResponse{})
	s.messageCounter = 0
	return err
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
	err := s.sendCommand(ctx, conn, pingPong, &pingPong)
	if err != nil {
		return err
	} else if !bytes.Equal(data, pingPong) {
		return errors.New("pong response incorrect")
	}

	return nil
}

// GetPublicKey retrieves the public half of an asymmetric keypair in
// the HSM.
//
// The return public key will be one of an [*ecdsa.PublicKey],
// [ed25519.PublicKey], or an [*rsa.PublicKey].
func (s *Session) GetPublicKey(ctx context.Context, conn Connector, keyID ObjectID) (PublicKey, error) {
	cmd := yubihsm.GetPublicKeyCommand{
		KeyID: keyID,
	}
	var rsp yubihsm.GetPublicKeyResponse
	err := s.sendCommand(ctx, conn, &cmd, &rsp)
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
func (s *Session) LoadKeyPair(ctx context.Context, conn Connector, label string) (KeyPair, error) {
	cmd := yubihsm.ListObjectsCommand{
		yubihsm.TypeFilter(yubihsm.TypeAsymmetricKey),
		yubihsm.LabelFilter(label),
	}
	var rsp yubihsm.ListObjectsResponse
	err := s.sendCommand(ctx, conn, cmd, &rsp)
	if err != nil {
		return KeyPair{}, err
	} else if len(rsp) == 0 {
		return KeyPair{}, fmt.Errorf("could not find asymmetric-key labeled %q", label)
	} else if len(rsp) > 1 {
		// This should be impossible, keys are identified via
		// the (type, ID) pair.
		return KeyPair{}, fmt.Errorf("HSM error: found %d asymmetric-keys labeled %q", len(rsp), label)
	}

	keyID := rsp[0].Object
	public, err := s.GetPublicKey(ctx, conn, keyID)
	if err != nil {
		return KeyPair{}, err
	}

	return KeyPair{public, keyID}, nil
}

func (s *Session) calculateCMAC(cmd yubihsm.CommandID, session byte, contents []byte) (k SessionKey) {
	// Use the receive MAC key for response messages
	key := s.macKey
	if cmd >= yubihsm.CommandResponse {
		key = s.rmacKey
	}

	// Keys are hardcoded to 16 bytes; cipher and CMAC construction
	// cannot fail.
	block, _ := aes.NewCipher(key[:])
	mac, _ := cmac.New(block)

	// Compute the CMAC over the chaining MAC, the message header,
	// and its contents.
	l := 1 + macLength + len(contents)
	header := [4]byte{byte(cmd), byte(l >> 8), byte(l), session}
	_, _ = mac.Write(s.macChaining[:])
	_, _ = mac.Write(header[:])
	_, _ = mac.Write(contents)

	// CMAC produces 16 bytes so hash directly into the returned key.
	mac.Sum(k[:0])
	return k
}

func (s *Session) sendCommand(ctx context.Context, conn Connector, cmd yubihsm.Command, rsp yubihsm.Response) error {
	if s.messageCounter == 0 {
		return ErrNotAuthenticated
	} else if s.messageCounter >= maxMessagesBeforeRekey {
		return ErrReauthenticationRequired
	}

	// While the largest command supported is ~2kB, this should be
	// large enough for the majority of commands sent without causing
	// too much heap spillage.
	var buf [256]byte

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

	// Send the command, and verify the session message response
	// envelope.
	message, err := conn.SendCommand(ctx, message)
	if err != nil {
		return err
	}

	message, err = s.decryptSessionResponse(block, iv, message)
	if err != nil {
		return err
	}

	// Validate the inner message header correctness.
	return yubihsm.ParseResponse(cmd.ID(), rsp, message)
}

// encryptThenMAC encrypte the message in-place then computes the message
// CMAC and writes it in the final 8 bytes of the message. Space for the
// header and MAC must be allocated at the front and back.
//
// Returns the AES block cipher and IV which can be used to decrypt the
// response.
func (s *Session) encryptThenMAC(message []byte) (cipher.Block, []byte) {
	// Create the CBC IV: 16 bytes; 12 zeroes and and 32-bit counter.
	// The serialized counter is encrypted with the session encryption
	// key to result in the IV.
	//
	// Increment the counter early to ensure an IV is never reused.
	var iv [aes.BlockSize]byte
	yubihsm.Put32(iv[len(iv)-4:], s.messageCounter)
	s.messageCounter++
	block, _ := aes.NewCipher(s.encryptionKey[:])
	block.Encrypt(iv[:], iv[:])

	// Encrypt the serialized and padded inner message.
	inner := message[sessionHeaderLength : len(message)-macLength]
	cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(inner, inner)

	// The appended MAC is the first 8 bytes of the truncated session
	// chaining MAC.
	s.macChaining = s.calculateCMAC(yubihsm.CommandSessionMessage, s.sessionID, inner)
	copy(message[len(message)-macLength:], s.macChaining[:macLength])

	return block, iv[:]
}

func (s *Session) decryptSessionResponse(block cipher.Block, iv, message []byte) ([]byte, error) {
	if len(message) < sessionHeaderLength+yubihsm.HeaderLength+macLength {
		// Four bytes in outer session message, three bytes inner,
		// eight bytes of MAC.
		return nil, ErrInvalidMessage
	} else if len(message)%aes.BlockSize != sessionHeaderLength+macLength {
		// Padding of the inner message is incorrect.
		return nil, ErrInvalidMessage
	}

	msgCmdID, msgLen := yubihsm.ParseHeader(message)
	if msgCmdID != yubihsm.ResponseSessionMessage {
		return nil, ErrInvalidMessage
	} else if msgLen != len(message)-yubihsm.HeaderLength {
		return nil, ErrInvalidMessage
	} else if message[yubihsm.HeaderLength] != s.sessionID {
		// TODO: need to synchronize across sessions!
		return nil, fmt.Errorf("session %d received response for session %d", s.sessionID, message[3])
	}

	// Verify the response MAC by comparing it to the expected value.
	inner := message[sessionHeaderLength : len(message)-macLength]
	validMAC := s.calculateCMAC(yubihsm.ResponseSessionMessage, s.sessionID, inner)
	recvedMAC := message[len(message)-macLength:]
	if subtle.ConstantTimeCompare(validMAC[:macLength], recvedMAC) != 1 {
		return nil, ErrIncorrectMAC
	}

	// Decrypt the inner response message.
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(inner, inner)
	return inner, nil
}
