package yubihsm

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"strings"
	"testing"

	yubihsm "github.com/nholstein/yubihsm/internal"
)

const MaxMessagesBeforeRekey = maxMessagesBeforeRekey

// Ensure we implement the crypto quasi-standard.
var _ cryptoPrivateKey = &KeyPair{}

type (
	CryptoPrivateKey = cryptoPrivateKey
	CryptoDecrypter  = cryptoDecrypter
)

func TestGenerateDefaultKey(t *testing.T) {
	t.Parallel()
	encKey, macKey := deriveAuthenticationKeys("password")
	t.Logf(`
var (
	defaultEncryptionKey = %#v
	defaultMACKey        = %#v
)
`, encKey, macKey)
}

func TestReadFullOrErr(t *testing.T) {
	rd := strings.NewReader("ElevenBytes")
	buf, err := readFullOrErr(rd, 12)
	if buf != nil || err == nil {
		t.Errorf("%x, %v", buf, err)
	}
}

func InvalidRand() AuthenticationOption {
	return func(_ *Session, c *authConfig) error {
		c.rand = strings.NewReader("short")
		return nil
	}
}

func ReplayHostChallenges(hostChallenges [][8]byte, options ...AuthenticationOption) []AuthenticationOption {
	var hostChallenge bytes.Buffer
	for _, c := range hostChallenges {
		_, _ = hostChallenge.Write(c[:])
	}

	return append(options, func(_ *Session, c *authConfig) error {
		c.rand = &hostChallenge
		return nil
	})
}

func (s *Session) SessionID() byte {
	return s.sessionID
}

func (s *Session) GetPublicKey(ctx context.Context, conn Connector, keyID ObjectID) (yubihsm.PublicKey, error) { //nolint:ireturn
	return s.getPublicKey(ctx, conn, keyID)
}

func (s *Session) EncryptResponse(response []byte, trim int) []byte {
	out := make([]byte, 4+len(response), 4+15+8+len(response))
	const pad = "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	padding := aes.BlockSize - len(out[4:])%aes.BlockSize
	out = append(out, pad[:padding+macLength]...)

	s.lock.Lock()
	defer s.lock.Unlock()

	yubihsm.Put8(out[0:], yubihsm.ResponseSessionMessage)
	yubihsm.Put16(out[1:], len(out)-yubihsm.HeaderLength)
	yubihsm.Put8(out[yubihsm.HeaderLength:], s.sessionID)

	inner := out[4 : len(out)-macLength]
	copy(inner, response)

	var iv [aes.BlockSize]byte
	yubihsm.Put32(iv[len(iv)-4:], s.messageCounter-1)
	block, _ := aes.NewCipher(s.encryptionKey[:])
	block.Encrypt(iv[:], iv[:])
	cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(inner, inner)

	inner = inner[:len(inner)-trim]
	out = out[:len(out)-trim]

	mac := calculateCMAC(s.rmacKey, s.macChaining, yubihsm.ResponseSessionMessage, s.sessionID, inner)
	copy(out[len(out)-macLength:], mac[:])

	return out
}

func SessionFuzzResponseParsing(authenticated *Session) func(*testing.T, []byte) {
	session := Session{session: authenticated.session}

	return func(t *testing.T, in []byte) {
		t.Parallel()
		var iv [aes.BlockSize]byte
		yubihsm.Put32(iv[len(iv)-4:], session.messageCounter)
		block, _ := aes.NewCipher(session.encryptionKey[:])
		block.Encrypt(iv[:], iv[:])

		decrypt := decryptResponse{session.rmacKey, session.macChaining, block, iv[:], session.SessionID()}
		_, _ = decrypt.decryptSessionResponse(in)
	}
}
