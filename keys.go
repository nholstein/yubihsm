package yubihsm

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"io"

	yubihsm "github.com/nholstein/yubihsm/internal"
)

// PublicKey is the strongly-typed [crypto.PublicKey]
type PublicKey = yubihsm.PublicKey

// KeyPair manages either an RSA, ECDSA, or Ed25519 key on a YubiHSM2.
type KeyPair struct {
	publicKey PublicKey
	keyID     ObjectID
}

// Public returns the key's public half.
//
// It will be either an [rsa.PublicKey], [ecdsa.PublicKey], or [ed25519.PublicKey]
// depending upon the type of the key in the YubiHSM.
func (k *KeyPair) Public() PublicKey {
	return k.publicKey
}

// Sign the message [digest] in the YubiHSM and return the signature.
//
// This mimics the semantics of [crypto.Signer.Sign], in particular the
// value of [opt]. See the details of [rsa.PrivateKey.Sign] and
// [ecdsa.PrivateKey.Sign] for additional details.
//
// This function will fail if the HSM key type is incompatible with
// decryption or if the [Effective Capabilities] are insufficient.
//
// [Effective Capabilities]: https://developers.yubico.com/YubiHSM2/Concepts/Effective_Capabilities.html
func (k *KeyPair) Sign(ctx context.Context, conn Connector, session *Session, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var cmd yubihsm.Command
	switch pub := k.publicKey.(type) {
	case *ecdsa.PublicKey:
		cmd = &yubihsm.SignECDSACommand{
			KeyID:  k.keyID,
			Digest: digest,
		}

	case ed25519.PublicKey:
		// opts should be [crypto.Hash(0)], but be flexible and
		// only check to ensure Ed25519ph wasn't specified.
		if opts != nil && opts.HashFunc() == crypto.SHA512 {
			return nil, errors.New("Ed25519ph is not supported by the YubiHSM2")
		}
		cmd = &yubihsm.SignEdDSACommand{
			KeyID:   k.keyID,
			Message: digest,
		}

	case *rsa.PublicKey:
		pss, ok := opts.(*rsa.PSSOptions)
		if ok {
			// from Go crypto/rsa/pss.go
			hash := pss.Hash
			saltLen := pss.SaltLength
			switch saltLen {
			case rsa.PSSSaltLengthAuto:
				saltLen = (pub.N.BitLen()-1+7)/8 - 2 - hash.Size()
				if saltLen < 0 {
					return nil, rsa.ErrMessageTooLong
				}
				saltLen = hash.Size()
			case rsa.PSSSaltLengthEqualsHash:
				saltLen = hash.Size()
			default:
				// If we get here saltLength is either > 0 or < -1, in the
				// latter case we fail out.
				if saltLen <= 0 {
					return nil, errors.New("crypto/rsa: PSSOptions.SaltLength cannot be negative")
				}
			}

			cmd = &yubihsm.SignPSSCommand{
				KeyID:   k.keyID,
				MGF1:    hash,
				SaltLen: uint16(saltLen),
				Digest:  digest,
			}
		} else {
			cmd = &yubihsm.SignPKCS1v15Command{
				KeyID:  k.keyID,
				Digest: digest,
			}
		}

	default:
		panic("unimplemented signer")
	}

	var rsp yubihsm.SignResponse
	err := session.sendCommand(ctx, conn, cmd, &rsp)
	if err != nil {
		return nil, err
	}

	return rsp, nil
}

// AsCryptoSigner wraps the keypair into a type which can be used with
// the Go standard library's [crypto.Signer].
//
// It does this by embedding the provided [ctx], [conn], and [session]
// into the returned object. This is non-idiomatic; particularly wrapping
// a [context.Context] into a returned structure contradicts standard
// practice.
//
// However, this is the only approach which matches the API of [crypto.Signer].
// Use of [KeyPair.Sign] should be preferred whenever compatibility with
// the standard library isn't needed.
//
// This does not confirm that the HSM key is compatible with signing,
// nor whether the [Effective Capabilities] are sufficient.
//
// [Effective Capabilities]: https://developers.yubico.com/YubiHSM2/Concepts/Effective_Capabilities.html
func (k *KeyPair) AsCryptoSigner(ctx context.Context, conn Connector, session *Session) crypto.Signer {
	return &cryptoSigner{
		keyPair: *k,
		session: session,
		conn:    conn,
		ctx:     ctx,
	}
}

// Decrypt the [message] in the YubiHSM and return the plaintext.
//
// This mimics the semantics of [crypto.Signer.Sign], in particular the
// value of [opt]. See the details of [rsa.PrivateKey.Decrypt].
//
// This function will fail if the HSM key type is incompatible with
// decryption or if the [Effective Capabilities] are insufficient.
//
// [Effective Capabilities]: https://developers.yubico.com/YubiHSM2/Concepts/Effective_Capabilities.html
func (k *KeyPair) Decrypt(_ context.Context, _ Connector, _ *Session, _ []byte, _ crypto.DecrypterOpts) ([]byte, error) {
	return nil, errors.New("implement me")
}

// AsCryptoDecrypter wraps the keypair into a type which can be used with
// the Go standard library's [crypto.Decrypter].
//
// It does this by embedding the provided [ctx], [conn], and [session]
// into the returned object. This is non-idiomatic; particularly wrapping
// a [context.Context] into a returned structure contradicts standard
// practice.
//
// However, this is the only approach which matches the API of [crypto.Decrypter].
// Use of [KeyPair.Sign] should be preferred whenever compatibility with
// the standard library isn't needed.
//
// This does not confirm that the HSM key is compatible with signing,
// nor whether the [Effective Capabilities] are sufficient.
//
// [Effective Capabilities]: https://developers.yubico.com/YubiHSM2/Concepts/Effective_Capabilities.html
func (k *KeyPair) AsCryptoDecrypter(ctx context.Context, conn Connector, session *Session) crypto.Decrypter {
	return &cryptoDecrypter{
		keyPair: *k,
		session: session,
		conn:    conn,
		ctx:     ctx,
	}
}

type cryptoSigner struct {
	keyPair KeyPair
	session *Session
	conn    Connector
	ctx     context.Context
}

func (s *cryptoSigner) Public() crypto.PublicKey {
	return s.keyPair.publicKey
}

func (s *cryptoSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.keyPair.Sign(s.ctx, s.conn, s.session, digest, opts)
}

type cryptoDecrypter struct {
	keyPair KeyPair
	session *Session
	conn    Connector
	ctx     context.Context
}

func (d *cryptoDecrypter) Public() crypto.PublicKey {
	return d.keyPair.publicKey
}

func (d *cryptoDecrypter) Decrypt(_ io.Reader, message []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return d.keyPair.Decrypt(d.ctx, d.conn, d.session, message, opts)
}
