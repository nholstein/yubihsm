package yubihsm

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"strconv"
	"testing"
)

// loadReplayKey creates a [Session] and [KeyPair] using replayed
// yubihsm-connector logs. The returned session is automatically
// authenticated and key loaded by label.
func loadReplayKey(t *testing.T, yubihsmConnectorLog, keyLabel string) (context.Context, *replayConnector, *Session, KeyPair) {
	t.Helper()
	ctx, conn, session := loadReplaySession(t, yubihsmConnectorLog)
	private, err := session.LoadKeyPair(ctx, conn, keyLabel)
	if err != nil {
		t.Fatalf("session.LoadKeyPair(\"test-key\"): %v", err)
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
}

// Used to record logs from a real YubiHSM2.
func httpSession(t *testing.T, _, label string) (context.Context, Connector, *Session, KeyPair) {
	ctx := testingContext(t)
	var conn HTTPConnector
	var session Session
	session.testAuthenticate(ctx, t, &conn)

	private, err := session.LoadKeyPair(ctx, &conn, label)
	if err != nil {
		t.Helper()
		t.Fatalf("session.LoadKeyPair(\"test-key\"): %v", err)
	}

	return ctx, &conn, &session, private
}

func testKeyRSA(t *testing.T, bits int) {
	hashed := sha256.Sum256([]byte("test RSA message"))
	hash := crypto.SHA256

	t.Run("sign-pkcs1v15", func(t *testing.T) {
		log := fmt.Sprintf("sign-rsa%d-pkcs1v15.log", bits)
		label := fmt.Sprintf("test-rsa%d", bits)
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
		label := fmt.Sprintf("test-rsa%d", bits)
		ctx, conn, session, private := loadReplayKey(t, log, label)
		//ctx, conn, session, private := httpSession(t, log, label)
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

	t.Run("decrypt", func(t *testing.T) {

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
