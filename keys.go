package yubihsm

import (
	"cmp"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"

	yubihsm "github.com/nholstein/yubihsm/internal"
)

// KeyPair manages either an RSA, ECDSA, or Ed25519 key on a YubiHSM2.
//
// A KeyPair is a [crypto.PrivateKey], but it does not directly implement
// either [crypto.Signer] or [crypto.Decrypter]. This is because invoking
// a command on an HSM requires a [context.Context] parameter, which is
// not supported by the [crypto] API.
//
// Instead, use the [KeyPair.Sign] function directly, or used the
// [KeyPair.AsCryptoSigner] to wrap a (KeyPair, context) pair into a
// signing key object. The equivalent [KeyPair.Decrypt] and
// [KeyPair.AsCryptoDecrypter] are used to obtain a decryption key.
type KeyPair struct {
	publicKey yubihsm.PublicKey
	keyID     ObjectID
}

// Public returns the public key. It implements [crypto.PrivateKey].
//
// It will be either an [rsa.PublicKey], [ecdsa.PublicKey], or [ed25519.PublicKey]
// depending upon the type of the key in the YubiHSM.
func (k *KeyPair) Public() crypto.PublicKey {
	return k.publicKey
}

// Equal checks if two private keys are equal. It implements [crypto.PrivateKey].
//
// This checks for logical equivalency of the keys; not if they are the
// exact same objects on the same YubiHSM2. As an example, a private key
// imported to multiple HSMs would compare equal, even if object IDs did
// not match.
func (k *KeyPair) Equal(x crypto.PrivateKey) bool {
	rhs, ok := x.(cryptoPrivateKey)
	return ok && k.publicKey.Equal(rhs.Public())
}

// cryptoPrivateKey is the interface of all [crypto.PrivateKey]s.
type cryptoPrivateKey interface {
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
}

// Sign the message [digest] in the YubiHSM and return the signature.
//
// This mimics the semantics of [crypto.Signer.Sign], in particular the
// value of [opt]. See the details of [rsa.PrivateKey.Sign] and
// [ecdsa.PrivateKey.Sign] for additional details. Both PKCS1v1.5 and
// PSS signatures are supported with RSA keys. Only basic Ed25519
// signatures are supported; the YubiHSM2 supports neither the Ed25519ph
// or Ed25519ctx variants.
//
// This function will fail if the HSM key type is incompatible with
// decryption or if the [Effective Capabilities] are insufficient.
//
// [Effective Capabilities]: https://developers.yubico.com/YubiHSM2/Concepts/Effective_Capabilities.html
func (k *KeyPair) Sign(ctx context.Context, conn Connector, session *Session, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	switch pub := k.publicKey.(type) {
	case *ecdsa.PublicKey:
		return k.sign(ctx, conn, session, &yubihsm.SignECDSACommand{
			KeyID:  k.keyID,
			Digest: digest,
		})

	case ed25519.PublicKey:
		return k.signEd25519(ctx, conn, session, digest, opts)

	case *rsa.PublicKey:
		return k.signRSA(ctx, conn, session, pub, digest, opts)

	default:
		panic("unimplemented signer")
	}
}

// As of Go 1.21.4. the documentation for [ed225519.PrivateKey.Sign] is
// incomplete, as it does not mention Ed25519ctx. This uses the logic
// actually implemented in the signing function.
func (k *KeyPair) signEd25519(ctx context.Context, conn Connector, session *Session, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash := opts.HashFunc()
	context := ""
	if opts, ok := opts.(*ed25519.Options); ok {
		context = opts.Context
	}

	switch {
	case hash == crypto.SHA512: // Ed25519ph
		return nil, errors.New("Ed25519ph is not supported by the YubiHSM2")

	case hash == crypto.Hash(0) && context != "": // Ed25519ctx
		return nil, errors.New("Ed25519ctx is not supported by the YubiHSM2")

	case hash == crypto.Hash(0): // Ed25519
		return k.sign(ctx, conn, session, &yubihsm.SignEdDSACommand{
			KeyID:   k.keyID,
			Message: digest,
		})

	default:
		return nil, errors.New("ed25519: expected opts.HashFunc() zero (unhashed message, for standard Ed25519) or SHA-512 (for Ed25519ph)")
	}
}

func (k *KeyPair) signRSA(ctx context.Context, conn Connector, session *Session, pub *rsa.PublicKey, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	pss, ok := opts.(*rsa.PSSOptions)
	if !ok {
		return k.sign(ctx, conn, session, &yubihsm.SignPKCS1v15Command{
			KeyID:  k.keyID,
			Digest: digest,
		})
	}

	hash, saltLen, err := pssOptions(pub, pss)
	if err != nil {
		return nil, err
	}

	return k.sign(ctx, conn, session, &yubihsm.SignPSSCommand{
		KeyID:   k.keyID,
		MGF1:    hash,
		SaltLen: uint16(saltLen),
		Digest:  digest,
	})
}

func (k *KeyPair) sign(ctx context.Context, conn Connector, session *Session, cmd yubihsm.Command) ([]byte, error) {
	var rsp yubihsm.SignResponse
	err := session.sendCommand(ctx, conn, false, cmd, &rsp)
	return rsp, err
}

// pssOptions is copied from Go crypto/rsa/pss.go.
func pssOptions(pub *rsa.PublicKey, pss *rsa.PSSOptions) (crypto.Hash, int, error) {
	hash := pss.Hash
	saltLen := pss.SaltLength
	switch saltLen {
	case rsa.PSSSaltLengthAuto:
		saltLen = (pub.N.BitLen()-1+7)/8 - 2 - hash.Size() //nolint:gomnd
		if saltLen < 0 {
			return 0, 0, rsa.ErrMessageTooLong
		}

	case rsa.PSSSaltLengthEqualsHash:
		saltLen = hash.Size()

	default:
		// If we get here saltLength is either > 0 or < -1, in the
		// latter case we fail out.
		if saltLen <= 0 {
			return 0, 0, errors.New("crypto/rsa: PSSOptions.SaltLength cannot be negative or greater than 65535")
		}
	}

	if saltLen >= 1<<16 {
		return 0, 0, errors.New("RSA PSS salt too long")
	}

	return hash, saltLen, nil
}

// AsCryptoSigner wraps the keypair into a type which can be used with
// the Go standard library's [crypto.Signer]. The returned key also
// defines an Equal() method to implement [crypto.PrivateKey].
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
func (k *KeyPair) Decrypt(ctx context.Context, conn Connector, session *Session, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	_, ok := k.publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("unsupported crypto.Decrypter")
	}

	switch o := opts.(type) {
	case nil:
		return k.decrypt(ctx, conn, session, &yubihsm.DecryptPKCS1v15Command{
			KeyID:      k.keyID,
			CipherText: ciphertext,
		})

	case *rsa.PKCS1v15DecryptOptions:
		rsp, err := k.decrypt(ctx, conn, session, &yubihsm.DecryptPKCS1v15Command{
			KeyID:      k.keyID,
			CipherText: ciphertext,
		})

		if o.SessionKeyLen > 0 && errors.Is(err, yubihsm.ErrRsaDecryptFailed) {
			return readFullOrErr(rand.Reader, o.SessionKeyLen)
		}

		return rsp, err

	case *rsa.OAEPOptions:
		return k.decrypt(ctx, conn, session, &yubihsm.DecryptOAEPCommand{
			KeyID:      k.keyID,
			MGF1:       cmp.Or(o.MGFHash, o.Hash),
			LabelHash:  o.Hash,
			CipherText: ciphertext,
			Label:      o.Label,
		})

	default:
		return nil, errors.New("unsupported RSA decryption algorithm")
	}
}

func (k *KeyPair) decrypt(ctx context.Context, conn Connector, session *Session, cmd yubihsm.Command) ([]byte, error) {
	var rsp yubihsm.DecryptResponse
	err := session.sendCommand(ctx, conn, false, cmd, &rsp)
	return rsp, err
}

// readFullOrErr extends reads exactly [n] bytes or else it returns an
// error. (Contrast to [io.ReadFull] or [crypto/rand.Read], either of
// which can return a non-nil buffer with a non-nill error.
func readFullOrErr(rd io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	nn, err := io.ReadFull(rd, buf)
	if nn != n {
		return nil, err
	}
	return buf, nil
}

// AsCryptoDecrypter wraps the keypair into a type which can be used with
// the Go standard library's [crypto.Decrypter]. The returned key also
// defines an Equal() method to implement [crypto.PrivateKey].
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
	ctx     context.Context //nolint:containedctx
}

// Equal implements [crypto.PrivateKey].
func (s *cryptoSigner) Equal(x crypto.PrivateKey) bool {
	return s.keyPair.Equal(x)
}

// Public implements [crypto.PrivateKey] and [crypto.Signer].
func (s *cryptoSigner) Public() crypto.PublicKey {
	return s.keyPair.publicKey
}

// Sign implements [crypto.PrivateKey] and [crypto.Signer].
func (s *cryptoSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.keyPair.Sign(s.ctx, s.conn, s.session, digest, opts)
}

type cryptoDecrypter struct {
	keyPair KeyPair
	session *Session
	conn    Connector
	ctx     context.Context //nolint:containedctx
}

// Equal implements [crypto.PrivateKey].
func (d *cryptoDecrypter) Equal(x crypto.PrivateKey) bool {
	return d.keyPair.Equal(x)
}

// Public implements [crypto.PrivateKey] and [crypto.Decrypter].
func (d *cryptoDecrypter) Public() crypto.PublicKey {
	return d.keyPair.publicKey
}

// Decrypt implements [crypto.Decrypter].
func (d *cryptoDecrypter) Decrypt(_ io.Reader, message []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return d.keyPair.Decrypt(d.ctx, d.conn, d.session, message, opts)
}
