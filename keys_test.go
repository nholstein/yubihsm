package yubihsm

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"
	"strconv"
	"testing"
)

// loadReplayKey creates a [Session] and [KeyPair] using replayed
// yubihsm-connector logs. The returned session is automatically
// authenticated and key loaded by label.
func loadReplayKey(t *testing.T, yubihsmConnectorLog, label string) (context.Context, *replayConnector, *Session, KeyPair) {
	t.Helper()
	ctx, conn, session := loadReplaySession(t, yubihsmConnectorLog)
	private, err := session.LoadKeyPair(ctx, conn, label)
	if err != nil {
		t.Fatalf("session.LoadKeyPair(%q): %v", label, err)
	}

	return ctx, conn, session, private
}

func TestKeyECDSASign(t *testing.T) {
	digest := sha256.Sum256([]byte("test ECDSA message"))

	t.Run("yubihsm", func(t *testing.T) {
		ctx, conn, session, private := loadReplayKey(t, "sign-p256.log", "p256")
		signature, err := private.Sign(ctx, conn, session, digest[:], crypto.SHA256)
		if err != nil {
			t.Errorf("private.Sign(): %v", err)
		}
		t.Logf("signature: %x", signature)

		public := private.Public().(*ecdsa.PublicKey)
		if !ecdsa.VerifyASN1(public, digest[:], signature) {
			t.Errorf("signature verification failed")
		}
	})

	t.Run("crypto", func(t *testing.T) {
		ctx, conn, session, private := loadReplayKey(t, "sign-p256.log", "p256")
		signer := private.AsCryptoSigner(ctx, conn, session)
		signature, err := signer.Sign(nil, digest[:], crypto.SHA256)
		if err != nil {
			t.Errorf("signer.Sign(): %v", err)
		}
		t.Logf("signature: %x", signature)

		public := signer.Public().(*ecdsa.PublicKey)
		if !ecdsa.VerifyASN1(public, digest[:], signature) {
			t.Errorf("signature verification failed")
		}
	})

	t.Run("can't decrypt", func(t *testing.T) {
		ctx, conn, session, private := loadReplayKey(t, "sign-p256.log", "p256")
		_, err := private.Decrypt(ctx, conn, session, []byte("12345"), nil)
		if err == nil {
			t.Errorf("decrypting using a P-256 key should fail")
		}
		_, _ = private.Sign(ctx, conn, session, digest[:], crypto.SHA256)
	})
}

func TestKeyEd25519Sign(t *testing.T) {
	message := []byte("test Ed25519 message")

	t.Run("yubihsm", func(t *testing.T) {
		ctx, conn, session, private := loadReplayKey(t, "sign-ed25519.log", "test-key")

		t.Run("unsupport Ed25519ph", func(t *testing.T) {
			digest := sha512.Sum512(message)
			_, err := private.Sign(ctx, conn, session, digest[:], crypto.SHA512)
			if err == nil {
				t.Errorf("Ed25519ph should fail as unsupported")
			}
		})

		signature, err := private.Sign(ctx, conn, session, message, nil)
		if err != nil {
			t.Errorf("private.Sign(): %v", err)
		}
		t.Logf("signature: %x", signature)

		public := private.Public().(ed25519.PublicKey)
		if !ed25519.Verify(public, message, signature) {
			t.Errorf("signature verification failed")
		}
	})

	t.Run("crypto", func(t *testing.T) {
		ctx, conn, session, private := loadReplayKey(t, "sign-ed25519.log", "test-key")
		signer := private.AsCryptoSigner(ctx, conn, session)
		signature, err := signer.Sign(nil, message, nil)
		if err != nil {
			t.Errorf("private.Sign(): %v", err)
		}
		t.Logf("signature: %x", signature)

		public := signer.Public().(ed25519.PublicKey)
		if !ed25519.Verify(public, message, signature) {
			t.Errorf("signature verification failed")
		}
	})

	t.Run("can't decrypt", func(t *testing.T) {
		ctx, conn, session, private := loadReplayKey(t, "sign-ed25519.log", "test-key")
		_, err := private.Decrypt(ctx, conn, session, []byte("12345"), nil)
		if err == nil {
			t.Errorf("decrypting using a Ed25519 key should fail")
		}
		_, _ = private.Sign(ctx, conn, session, message, nil)
	})
}

func httpSession(t *testing.T, log, label string) (context.Context, Connector, *Session, KeyPair) {
	ctx := testingContext(t)
	conn := logMessagesConnector{T: t}
	var session Session
	session.testAuthenticate(ctx, t, &conn)

	private, err := session.LoadKeyPair(ctx, &conn, label)
	if err != nil {
		t.Helper()
		t.Fatalf("session.LoadKeyPair(%q): %v", label, err)
	}

	conn.cleanup(t, log)
	return ctx, &conn, &session, private
}

func testKeyRSA(t *testing.T, bits int) {
	message := []byte("test plaintext")
	hashed := sha256.Sum256([]byte("test RSA message"))
	hash := crypto.SHA256
	label := fmt.Sprintf("test-rsa%d", bits)

	t.Run("sign-pkcs1v15", func(t *testing.T) {
		log := fmt.Sprintf("sign-rsa%d-pkcs1v15.log", bits)
		ctx, conn, session, private := loadReplayKey(t, log, label)
		signer := private.AsCryptoSigner(ctx, conn, session)
		signature, err := signer.Sign(nil, hashed[:], hash)
		if err != nil {
			t.Errorf("signer.Sign(): %v", err)
		}

		public := signer.Public().(*rsa.PublicKey)
		err = rsa.VerifyPKCS1v15(public, hash, hashed[:], signature)
		if err != nil {
			t.Errorf("rsa.VerifyPKCS1v15(): %v", err)
		}
	})

	t.Run("sign-pss", func(t *testing.T) {
		log := fmt.Sprintf("sign-rsa%d-pss.log", bits)
		ctx, conn, session, private := loadReplayKey(t, log, label)
		signer := private.AsCryptoSigner(ctx, conn, session)

		for _, saltLength := range []int{
			rsa.PSSSaltLengthAuto,
			rsa.PSSSaltLengthEqualsHash,
			32,
		} {
			opts := rsa.PSSOptions{
				Hash:       hash,
				SaltLength: saltLength,
			}
			signature, err := signer.Sign(nil, hashed[:], &opts)
			if err != nil {
				t.Errorf("signer.Sign(): %v", err)
			}

			public := signer.Public().(*rsa.PublicKey)
			err = rsa.VerifyPSS(public, hash, hashed[:], signature, &opts)
			if err != nil {
				t.Errorf("rsa.VerifyPSS(): %v", err)
			}
		}
	})

	loadDecryptKey := func(t *testing.T, alg, options string) (crypto.Decrypter, *rsa.PublicKey, io.Reader) {
		// The RSA encryption routines use crypto/randutil.MaybeReadByte
		// to add non-determinism when encrypting; even when
		// using a deterministic random reader. Since this skips
		// randomly skips a byte the solution is to always return
		// identical bytes.
		rand := bytes.NewReader(make([]byte, 4096))

		log := fmt.Sprintf("decrypt-rsa%d-%s-%s.log", bits, alg, options)
		ctx, conn, session, private := loadReplayKey(t, log, label)
		//ctx, conn, session, private := httpSession(t, log, label)
		t.Cleanup(func() {
			err := session.Close(ctx, conn)
			if err != nil {
				t.Errorf("session.Close(): %v", err)
			}
		})

		decrypter := private.AsCryptoDecrypter(ctx, conn, session)
		public := decrypter.Public().(*rsa.PublicKey)
		t.Logf("decrypter: %#v", decrypter)

		return decrypter, public, rand
	}

	checkDecryption := func(t *testing.T, plaintext []byte, err error) {
		if err != nil {
			t.Errorf("decrypter.Decrypt(): %v", err)
		}
		t.Logf("plaintext: %q", plaintext)
		if !bytes.Equal(plaintext, message) {
			t.Logf("message:   %q", message)
			t.Errorf("decryption failed")
		}
	}

	t.Run("decrypt-pkcs1v15", func(t *testing.T) {
		loadDecryptKeyPKCS1v15 := func(t *testing.T, options string) (crypto.Decrypter, []byte) {
			decrypter, public, rand := loadDecryptKey(t, "pkcs1v15", options)
			ciphertext, err := rsa.EncryptPKCS1v15(rand, public, message)
			if err != nil {
				t.Helper()
				t.Fatalf("rsa.EncryptPKCS1v15(): %v", err)
			}

			return decrypter, ciphertext
		}

		t.Run("no PKCS1v15DecryptOptions", func(t *testing.T) {
			decrypter, ciphertext := loadDecryptKeyPKCS1v15(t, "no")
			plaintext, err := decrypter.Decrypt(nil, ciphertext, nil)
			checkDecryption(t, plaintext, err)
		})

		t.Run("empty PKCS1v15DecryptOptions", func(t *testing.T) {
			decrypter, ciphertext := loadDecryptKeyPKCS1v15(t, "empty")
			var options rsa.PKCS1v15DecryptOptions
			plaintext, err := decrypter.Decrypt(nil, ciphertext, &options)
			checkDecryption(t, plaintext, err)
		})

		t.Run("set PKCS1v15DecryptOptions", func(t *testing.T) {
			decrypter, ciphertext := loadDecryptKeyPKCS1v15(t, "set")
			options := rsa.PKCS1v15DecryptOptions{
				SessionKeyLen: 32,
			}
			plaintext, err := decrypter.Decrypt(nil, ciphertext, &options)
			checkDecryption(t, plaintext, err)
		})

		t.Run("failed PKCS1v15DecryptOptions", func(t *testing.T) {
			decrypter, ciphertext := loadDecryptKeyPKCS1v15(t, "failed")

			corrupted := append([]byte{}, ciphertext...)
			corrupted[0] ^= 1

			options := rsa.PKCS1v15DecryptOptions{
				SessionKeyLen: 32,
			}
			plaintext, err := decrypter.Decrypt(nil, corrupted, &options)
			if err != nil {
				t.Errorf("decrypter.Decrypt(): %v", err)
			}
			t.Logf("plaintext: %q", plaintext)
			if bytes.Equal(plaintext, make([]byte, options.SessionKeyLen)) {
				t.Errorf("returned zeroed plaintext")
			} else if bytes.Equal(plaintext, message) {
				t.Errorf("should have returned random plaintext")
			}
		})
	})

	t.Run("decrypt-oaep", func(t *testing.T) {
		loadDecryptKeyOAEP := func(t *testing.T, options string) (crypto.Decrypter, []byte) {
			decrypter, public, rand := loadDecryptKey(t, "oaep", options)
			ciphertext, err := rsa.EncryptOAEP(crypto.SHA256.New(), rand, public, message, []byte(t.Name()))
			if err != nil {
				t.Helper()
				t.Fatalf("rsa.EncryptOAEP(): %v", err)
			}

			return decrypter, ciphertext
		}

		t.Run("simple", func(t *testing.T) {
			decrypter, ciphertext := loadDecryptKeyOAEP(t, "simple")

			t.Run("decrypt-error", func(t *testing.T) {
				_, err := decrypter.Decrypt(nil, ciphertext, &rsa.PSSOptions{})
				if err == nil {
					t.Errorf("decryption with bad options should fail")
				}
			})

			plaintext, err := decrypter.Decrypt(nil, ciphertext, &rsa.OAEPOptions{
				Hash:  crypto.SHA256,
				Label: []byte(t.Name()),
			})
			checkDecryption(t, plaintext, err)
		})
	})
}

func TestKeyRSA(t *testing.T) {
	for _, bits := range []int{2048, 3072, 4096} {
		t.Run(strconv.Itoa(bits), func(t *testing.T) {
			testKeyRSA(t, bits)
		})
	}
}

func TestKeyPairCoverage(t *testing.T) {
	t.Run("panic on bad key", func(t *testing.T) {
		defer func() {
			p := recover()
			if p == nil {
				t.Error("should have recovered a panic")
			} else {
				t.Logf("recovered panic: %v", p)
			}
		}()

		var (
			conn    HTTPConnector
			session Session
			private KeyPair
		)
		_, _ = private.Sign(context.Background(), &conn, &session, []byte("foobar"), nil)
		t.Error("should have panicked")
	})

	t.Run("sign error", func(t *testing.T) {
		message := []byte("test Ed25519 message")
		ctx, conn, session, private := loadReplayKey(t, "sign-ed25519.log", "test-key")
		signature, err := private.Sign(ctx, conn, session, message, nil)
		if err != nil {
			t.Fatalf("private.Sign(): %v", err)
		}
		signature, err = private.Sign(ctx, conn, session, message, nil)
		if signature != nil || err == nil {
			t.Errorf("private.Sign() should have failed on an emptied message log")
		}
	})
}
