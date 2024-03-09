package yubihsm

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"testing"

	yubihsm "github.com/nholstein/yubihsm/internal"
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
	t.Parallel()
	digest := sha256.Sum256([]byte("test ECDSA message"))

	t.Run("yubihsm", func(t *testing.T) {
		t.Parallel()
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
		t.Parallel()
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
		t.Parallel()
		ctx, conn, session, private := loadReplayKey(t, "sign-p256.log", "p256")
		_, err := private.Decrypt(ctx, conn, session, []byte("12345"), nil)
		if err == nil {
			t.Errorf("decrypting using a P-256 key should fail")
		}
		_, _ = private.Sign(ctx, conn, session, digest[:], crypto.SHA256)
	})
}

func TestKeyEd25519Sign(t *testing.T) {
	t.Parallel()
	message := []byte("test Ed25519 message")

	t.Run("yubihsm", func(t *testing.T) {
		t.Parallel()
		ctx, conn, session, private := loadReplayKey(t, "sign-ed25519.log", "test-key")

		t.Run("unsupport Ed25519ph", func(t *testing.T) {
			digest := sha512.Sum512(message)
			_, err := private.Sign(ctx, conn, session, digest[:], crypto.SHA512)
			if err == nil {
				t.Errorf("Ed25519ph should fail as unsupported")
			}
		})

		signature, err := private.Sign(ctx, conn, session, message, crypto.Hash(0))
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
		t.Parallel()
		ctx, conn, session, private := loadReplayKey(t, "sign-ed25519.log", "test-key")
		signer := private.AsCryptoSigner(ctx, conn, session)
		signature, err := signer.Sign(nil, message, crypto.Hash(0))
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
		t.Parallel()
		ctx, conn, session, private := loadReplayKey(t, "sign-ed25519.log", "test-key")
		_, err := private.Decrypt(ctx, conn, session, []byte("12345"), nil)
		if err == nil {
			t.Errorf("decrypting using a Ed25519 key should fail")
		}
		_, _ = private.Sign(ctx, conn, session, message, crypto.Hash(0))
	})
}

func testKeyRSA(t *testing.T, bits int) {
	message := []byte("test plaintext")
	hashed := sha256.Sum256([]byte("test RSA message"))
	hash := crypto.SHA256
	label := fmt.Sprintf("test-rsa%d", bits)

	t.Run("sign-pkcs1v15", func(t *testing.T) {
		t.Parallel()
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
		t.Parallel()
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
		t.Helper()

		// The RSA encryption routines use crypto/randutil.MaybeReadByte
		// to add non-determinism when encrypting; even when
		// using a deterministic random reader. Since this skips
		// randomly skips a byte the solution is to always return
		// identical bytes.
		rand := bytes.NewReader(make([]byte, 4096))

		log := fmt.Sprintf("decrypt-rsa%d-%s-%s.log", bits, alg, options)
		ctx, conn, session, private := loadReplayKey(t, log, label)
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
		t.Helper()

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
			t.Helper()

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

		t.Run("detect error", func(t *testing.T) {
			decrypter, ciphertext := loadDecryptKeyPKCS1v15(t, "no")
			plaintext, err := decrypter.Decrypt(nil, ciphertext, nil)
			checkDecryption(t, plaintext, err)

			key := decrypter.(*cryptoDecrypter)
			session := Session{session: key.session.session}
			response := sessionResponse{&session, [][]byte{{0x7f, 0, 1, 9}}}
			plaintext, err = key.keyPair.Decrypt(key.ctx, &response, &session, message, nil)
			var pErr yubihsm.Error
			if !errors.As(err, &pErr) || plaintext != nil {
				t.Errorf("should return protocol error")
			}
		})
	})

	t.Run("decrypt-oaep", func(t *testing.T) {
		loadDecryptKeyOAEP := func(t *testing.T, options string) (crypto.Decrypter, []byte) {
			t.Helper()
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
	t.Parallel()
	for _, bits := range []int{2048, 3072, 4096} {
		bits := bits

		t.Run(strconv.Itoa(bits), func(t *testing.T) {
			t.Parallel()
			testKeyRSA(t, bits)
		})
	}
}

func TestLoadKeyPairErrors(t *testing.T) {
	t.Parallel()
	checkNoKey := func(t *testing.T, key *KeyPair, err error) {
		t.Helper()
		if err == nil {
			t.Errorf("should have failed")
		} else if key.Public() != nil {
			t.Errorf("public key should be nil")
		}
	}

	t.Run("no key found", func(t *testing.T) {
		t.Parallel()
		ctx, conn, session := loadSessionResponse(t, yubihsm.CommandListObjects)
		key, err := session.LoadKeyPair(ctx, conn, "not-there")
		checkNoKey(t, &key, err)
	})

	t.Run("multiple keys found", func(t *testing.T) {
		t.Parallel()
		ctx, conn, session := loadSessionResponse(t, yubihsm.CommandListObjects,
			0x12, 0x34, uint8(yubihsm.TypeAsymmetricKey), 0,
			0x56, 0x78, uint8(yubihsm.TypeAsymmetricKey), 1,
		)
		key, err := session.LoadKeyPair(ctx, conn, "too-many")
		checkNoKey(t, &key, err)
	})

	t.Run("get key fails", func(t *testing.T) {
		t.Parallel()
		ctx, conn, session := loadSessionResponses(t,
			makeSessionResponse(yubihsm.CommandListObjects, 0x12, 0x34, uint8(yubihsm.TypeAsymmetricKey), 0),
			makeSessionResponse(yubihsm.CommandEcho, 0xff),
			makeSessionResponse(0x7f, 9),
		)
		key, err := session.LoadKeyPair(ctx, conn, "get-fails")
		checkNoKey(t, &key, err)
	})
}

func TestKeyPairCoverage(t *testing.T) {
	t.Run("panic on bad key", func(t *testing.T) {
		t.Parallel()

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
		t.Parallel()
		message := []byte("test Ed25519 message")
		ctx, conn, session, private := loadReplayKey(t, "sign-ed25519.log", "test-key")

		signature, err := private.Sign(ctx, conn, session, message, crypto.MD5)
		if signature != nil || err == nil {
			t.Fatalf("private.Sign(): should reject unsupported digest")
		}

		signature, err = private.Sign(ctx, conn, session, message, &ed25519.Options{
			Context: "Ed25519ctx is not supported",
		})
		if signature != nil || err == nil {
			t.Fatalf("private.Sign(): should reject Ed25519ctx")
		}

		t.Log("need to generate a valid signature to replay sign-eddsa command")
		_, err = private.Sign(ctx, conn, session, message, crypto.Hash(0))
		if err != nil {
			t.Fatalf("private.Sign(): %v", err)
		}

		signature, err = private.Sign(ctx, conn, session, message, crypto.Hash(0))
		if signature != nil || err == nil {
			t.Errorf("private.Sign() should have failed on an emptied message log")
		}
	})

	t.Run("load error", func(t *testing.T) {
		t.Parallel()
		message := []byte("test Ed25519 message")
		ctx, conn, session, private := loadReplayKey(t, "sign-ed25519.log", "test-key")
		_, err := private.Sign(ctx, conn, session, message, crypto.Hash(0))
		if err != nil {
			t.Fatalf("private.Sign(): %v", err)
		}

		public, err := session.getPublicKey(ctx, conn, 256)
		if err == nil || public != nil {
			t.Errorf("session.getPublicKey() should have failed on an emptied message log")
		}

		key, err := session.LoadKeyPair(ctx, conn, "P-256")
		if err == nil || key.Public() != nil {
			t.Errorf("session.LoadKeyPair() should have failed on an emptied message log")
		}
	})

	t.Run("RSA PSS options", func(t *testing.T) {
		t.Parallel()
		bits := 2048
		message := []byte("test plaintext")
		hashed := sha256.Sum256([]byte("test RSA message"))
		hash := crypto.SHA256
		log := fmt.Sprintf("sign-rsa%d-pss.log", bits)
		label := fmt.Sprintf("test-rsa%d", bits)

		ctx, conn, session, private := loadReplayKey(t, log, label)

		t.Run("negative salt length", func(t *testing.T) {
			signature, err := private.Sign(ctx, conn, session, message, &rsa.PSSOptions{
				Hash:       crypto.SHA256,
				SaltLength: -32,
			})
			if err == nil || signature != nil {
				t.Errorf("negative salt length should cause error")
			}
		})

		t.Run("failed auto salt length", func(t *testing.T) {
			// I'm not sure a way to make this fail without cheating?
			public := private.publicKey.(*rsa.PublicKey)
			n := public.N.Bytes()
			public.N.SetUint64(0xffffffffffffffff)

			signature, err := private.Sign(ctx, conn, session, message, &rsa.PSSOptions{
				Hash: crypto.SHA256,
			})
			if err == nil || signature != nil {
				t.Errorf("computed salt length should fail")
			}

			public.N.SetBytes(n)
		})

		t.Run("key still valid", func(t *testing.T) {
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
	})

	t.Run("bad random", func(t *testing.T) {
		t.Skip()
		ctx, _, session := loadSessionResponse(t, yubihsm.CommandDecryptPKCS1v15)
		key := KeyPair{
			publicKey: &rsa.PublicKey{
				N: big.NewInt(5),
				E: 3,
			},
			keyID: 1234,
		}

		// So unsafe. So, so unsafe.
		rd := rand.Reader
		defer func() { rand.Reader = rd }()
		rand.Reader = bytes.NewReader([]byte{1, 2, 3, 4, 5, 6, 7})

		// Return a YubiHSM2 error message to trigger generation
		// of a random session key.
		response := sessionResponse{session, [][]byte{{0x7f, 0, 1, 6}}}

		plaintext, err := key.Decrypt(ctx, &response, session, []byte{1, 2, 3, 4}, &rsa.PKCS1v15DecryptOptions{
			SessionKeyLen: 8,
		})
		if !errors.Is(err, io.ErrUnexpectedEOF) || plaintext != nil {
			t.Errorf("should have failed to read random session key: %x, %v", plaintext, err)
		}
	})
}
