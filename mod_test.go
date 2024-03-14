package yubihsm

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"

	yubihsm "github.com/nholstein/yubihsm/internal"
	"golang.org/x/crypto/pbkdf2"
)

const MaxMessagesBeforeRekey = maxMessagesBeforeRekey

// Ensure we implement the crypto quasi-standard.
var _ cryptoPrivateKey = &KeyPair{}

type (
	CryptoPrivateKey = cryptoPrivateKey
	CryptoDecrypter  = cryptoDecrypter
)

// Set to [true] when running tests to derive and save the default
// authentication key. Since this uses PBKDF2, which is generally
// considered not the preferred key derivation function, the key
// derivation is only used for the default password "password"; in
// all other cases random 32-byte keys are encouraged.
var flagGenerateDefaultKey bool

func init() {
	flag.BoolVar(&flagGenerateDefaultKey, "generate-default-key", false, "")
}

func generateDefaultKey() []byte {
	return pbkdf2.Key([]byte("password"), []byte("Yubico"), 10_000, 32, sha256.New)
}

func TestGenerateDefaultKey(t *testing.T) {
	t.Parallel()
	defaultAuthKey := generateDefaultKey()
	t.Logf("default key = %x", defaultAuthKey)

	if flagGenerateDefaultKey {
		out, err := os.Create("default-auth-key.go")
		if err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() {
			err = out.Close()
			if err != nil {
				t.Error(err)
			}
		})

		_, err = fmt.Fprintf(out, `// Code generated by go test github.com/nholstein/yubihsm -generate-default-key; DO NOT EDIT.

package yubihsm

// defaultAuthKey is the pre-derived default YubiHSM2 authentication key.
const defaultAuthKey = %q

func defaultEncryptionKey() (key SessionKey) {
	copy(key[:], defaultAuthKey[:len(key)])
	return
}

func defaultMACKey() (key SessionKey) {
	copy(key[:], defaultAuthKey[len(key):])
	return
}
`, defaultAuthKey)
		if err != nil {
			t.Error(err)
		}
	}
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
