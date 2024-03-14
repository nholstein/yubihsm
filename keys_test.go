package yubihsm_test

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
	"math/big"
	"strconv"
	"testing"

	"github.com/nholstein/yubihsm"
	internal "github.com/nholstein/yubihsm/internal"
)

// loadReplayKey creates a [yubihsm.Session] and [yubihsm.KeyPair] using replayed
// yubihsm-connector logs. The returned session is automatically
// authenticated and key loaded by label.
func loadReplayKey(t *testing.T, yubihsmConnectorLog, label string) (context.Context, testConnector, *yubihsm.Session, *yubihsm.KeyPair) {
	t.Helper()
	ctx, conn, session, _ := loadReplaySession(t, yubihsmConnectorLog)
	private, err := session.LoadKeyPair(ctx, conn, label)
	if err != nil {
		t.Fatalf("session.LoadKeyPair(%q): %v", label, err)
	}

	return ctx, conn, session, private
}

func TestCryptoPrivateKey(t *testing.T) {
	t.Parallel()

	_, conn, _, privP256 := loadReplayKey(t, "sign-p256.log", "p256")
	conn.flush()
	_, conn, _, privEd25519 := loadReplayKey(t, "sign-ed25519.log", "test-key")
	conn.flush()
	_, conn, _, privRsa := loadReplayKey(t, "sign-rsa2048-pss.log", "test-rsa2048")
	conn.flush()

	privs := []*yubihsm.KeyPair{privP256, privEd25519, privRsa}

	for _, k := range privs {
		for _, x := range privs {
			if k == x && !k.Equal(x) {
				t.Errorf("private key must equal itself")
			}
			if k != x && k.Equal(x) {
				t.Errorf("distinct private keys must not be equal")
			}
		}
	}

	// We have three separate private key types, and it's too easy
	// to mess up the crypto interface methods on these since it's
	// all untyped methods which take [any].
	//
	// Run a stupid large combination of [Equal] methods across a
	// combination of these types to ensure everything works as
	// expected. Since the [yubihsm.KeyPair.Equal] method winds up calling
	// [crypto.PrivateKey.Public] the [yubihsm.KeyPair.Public] method is
	// tested as well.

	signerP256 := privP256.AsCryptoSigner(nil, nil, nil)
	cryptoP256 := signerP256.(yubihsm.CryptoPrivateKey)
	if !cryptoP256.Equal(signerP256) ||
		!cryptoP256.Equal(cryptoP256) ||
		!cryptoP256.Equal(privP256) ||
		!privP256.Equal(signerP256) {
		t.Errorf("P256 signing key must equal P256 KeyPair")
	}
	for _, x := range []*yubihsm.KeyPair{privEd25519, privRsa} {
		if cryptoP256.Equal(x) || x.Equal(signerP256) {
			t.Errorf("P256 signing key must not be equal")
		}
	}

	decrypterRsa := privRsa.AsCryptoDecrypter(nil, nil, nil)
	cryptoRsa := decrypterRsa.(yubihsm.CryptoPrivateKey)
	if !cryptoRsa.Equal(decrypterRsa) ||
		!cryptoRsa.Equal(cryptoRsa) ||
		!cryptoRsa.Equal(privRsa) ||
		!privRsa.Equal(decrypterRsa) {
		t.Errorf("RSA decrypting key must equal RSA KeyPair")
	}
	for _, x := range []*yubihsm.KeyPair{privP256, privEd25519} {
		if cryptoRsa.Equal(x) || x.Equal(decrypterRsa) {
			t.Errorf("RSA decrypting key must not be equal")
		}
	}
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

		for _, p := range []any{private.Public(), signer.Public()} {
			public := p.(*ecdsa.PublicKey)
			if !ecdsa.VerifyASN1(public, digest[:], signature) {
				t.Errorf("signature verification failed")
			}
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

		for _, p := range []any{private.Public(), signer.Public()} {
			public := p.(*rsa.PublicKey)
			err = rsa.VerifyPKCS1v15(public, hash, hashed[:], signature)
			if err != nil {
				t.Errorf("rsa.VerifyPKCS1v15(): %v", err)
			}
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

			for _, p := range []any{private.Public(), signer.Public()} {
				public := p.(*rsa.PublicKey)
				err = rsa.VerifyPSS(public, hash, hashed[:], signature, &opts)
				if err != nil {
					t.Errorf("rsa.VerifyPSS(): %v", err)
				}
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

		if !public.Equal(private.Public()) {
			t.Error("mixed up the RSA public keys")
		}

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

		//t.Run("detect error", func(t *testing.T) {
		//	decrypter, ciphertext := loadDecryptKeyPKCS1v15(t, "no")
		//	plaintext, err := decrypter.Decrypt(nil, ciphertext, nil)
		//	checkDecryption(t, plaintext, err)
		//
		//	key := decrypter.(*yubihsm.CryptoDecrypter)
		//	session := yubihsm.Session{session: key.session.session}
		//	response := sessionResponse{&session, [][]byte{{0x7f, 0, 1, 9}}}
		//	plaintext, err = key.keyPair.Decrypt(key.ctx, &response, &session, message, nil)
		//	var pErr internal.Error
		//	if !errors.As(err, &pErr) || plaintext != nil {
		//		t.Errorf("should return protocol error")
		//	}
		//})
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
	checkNoKey := func(t *testing.T, key *yubihsm.KeyPair, err error) {
		t.Helper()
		if err == nil {
			t.Errorf("should have failed")
		} else if key != nil {
			t.Errorf("public key should be nil")
		}
	}

	t.Run("no key found", func(t *testing.T) {
		t.Parallel()
		ctx, conn, session := loadSessionResponse(t, internal.CommandListObjects)
		key, err := session.LoadKeyPair(ctx, conn, "not-there")
		checkNoKey(t, key, err)
	})

	t.Run("multiple keys found", func(t *testing.T) {
		t.Parallel()
		ctx, conn, session := loadSessionResponse(t, internal.CommandListObjects,
			0x12, 0x34, uint8(internal.TypeAsymmetricKey), 0,
			0x56, 0x78, uint8(internal.TypeAsymmetricKey), 1,
		)
		key, err := session.LoadKeyPair(ctx, conn, "too-many")
		checkNoKey(t, key, err)
	})

	t.Run("get key fails", func(t *testing.T) {
		t.Parallel()
		ctx, conn, session := loadSessionResponses(t,
			makeSessionResponse(internal.CommandListObjects, 0x12, 0x34, uint8(internal.TypeAsymmetricKey), 0),
			makeSessionResponse(internal.CommandEcho, 0xff),
			makeSessionResponse(0x7f, 9),
		)
		key, err := session.LoadKeyPair(ctx, conn, "get-fails")
		checkNoKey(t, key, err)
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
			conn    yubihsm.HTTPConnector
			session yubihsm.Session
			private yubihsm.KeyPair
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

		public, err := session.GetPublicKey(ctx, conn, 256)
		if err == nil || public != nil {
			t.Errorf("session.getPublicKey() should have failed on an emptied message log")
		}

		key, err := session.LoadKeyPair(ctx, conn, "P-256")
		if err == nil || key != nil {
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
			public := private.Public().(*rsa.PublicKey)
			n := public.N
			defer func() { public.N = n }()

			for _, bad := range []*big.Int{
				// Public modulus too small.
				big.NewInt(0x7fffffffffffffff),
				// Public modulus too large for sign-pss command.
				big.NewInt(0).Lsh(big.NewInt(1), 1_000_000),
			} {
				public.N = bad
				signature, err := private.Sign(ctx, conn, session, message, &rsa.PSSOptions{
					Hash: crypto.SHA256,
				})
				if err == nil || signature != nil {
					t.Errorf("computed salt length should fail")
				}
			}
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
}
