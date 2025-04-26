package yubihsm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"math/big"
)

// Challenge is a fixed-width challenge exchanged during authentication
// and used to derive session keys.
type Challenge [8]byte

// Cryptogram is a fixed-width challenge exchanged during authentication
// and used to derive session keys.
type Cryptogram [8]byte

// PublicKey is the strongly-typed [crypto.PublicKey].
type PublicKey interface {
	Equal(x crypto.PublicKey) bool
}

func makeCmd(out []byte, c Command, l int) []byte {
	return append(out, byte(c.ID()), byte(l>>8), byte(l))
}

func makeObjectDataCmd(out []byte, c Command, keyID ObjectID, data []byte) []byte {
	// 2 byte key ID plus data
	out = makeCmd(out, c, 2+len(data))
	return Append(Append16(out, keyID), data)
}

func Mgf1AlgorithmID(mgf1 crypto.Hash) AlgorithmID {
	//nolint:exhaustive
	switch mgf1 {
	case crypto.SHA1:
		return AlgorithmMGF1SHA1
	case crypto.SHA256:
		return AlgorithmMGF1SHA256
	case crypto.SHA384:
		return AlgorithmMGF1SHA384
	case crypto.SHA512:
		return AlgorithmMGF1SHA512
	default:
		// The HSM will flag an error
		return 0
	}
}

type EmptyResponse struct{}

func (EmptyResponse) Parse(b []byte) error {
	if len(b) != 0 {
		return errInvalidLength
	}
	return nil
}

type sliceResponse []byte

func (s *sliceResponse) Parse(b []byte) error {
	*s = b
	return nil
}

// Echo command and response type to/from YubiHSM2.
type Echo []byte //nolint:recvcheck

func (Echo) ID() CommandID {
	return CommandEcho
}

func (e Echo) Serialize(out []byte) []byte {
	out = makeCmd(out, e, len(e))
	return Append(out, e)
}

func (e *Echo) Parse(b []byte) error {
	*e = b
	return nil
}

type CreateSessionCommand struct {
	KeySetID      ObjectID
	HostChallenge Challenge
}

func (*CreateSessionCommand) ID() CommandID {
	return CommandCreateSession
}

func (c *CreateSessionCommand) Serialize(out []byte) []byte {
	out = makeCmd(out, c, 10)
	return Append(Append16(out, c.KeySetID), c.HostChallenge[:])
}

type CreateSessionResponse struct {
	SessionID      byte
	CardChallenge  Challenge
	CardCryptogram Cryptogram
}

func (r *CreateSessionResponse) Parse(b []byte) error {
	if len(b) != 17 {
		return errInvalidLength
	}

	r.SessionID = b[0]
	copy(r.CardChallenge[:], b[1:9])
	copy(r.CardCryptogram[:], b[9:17])

	return nil
}

type AuthenticateSessionCommand struct {
	SessionID      byte
	HostCryptogram Cryptogram
	CMAC           [8]byte
}

func (c *AuthenticateSessionCommand) ID() CommandID {
	return CommandAuthenticateSession
}

func (c *AuthenticateSessionCommand) Serialize(out []byte) []byte {
	out = makeCmd(out, c, 17)
	out = Append8(out, c.SessionID)
	out = Append(out, c.HostCryptogram[:])
	return Append(out, c.CMAC[:])
}

type AuthenticateSessionResponse = EmptyResponse

type CloseSessionCommand struct{}

func (c CloseSessionCommand) ID() CommandID {
	return CommandCloseSession
}

func (c CloseSessionCommand) Serialize(out []byte) []byte {
	return makeCmd(out, c, 0)
}

type CloseSessionResponse = EmptyResponse

type DeviceInfoCommand struct{}

func (DeviceInfoCommand) ID() CommandID {
	return CommandGetDeviceInfo
}

func (d DeviceInfoCommand) Serialize(out []byte) []byte {
	return makeCmd(out, d, 0)
}

type DeviceInfoResponse struct {
	Version    string
	Serial     uint32
	LogTotal   uint8
	LogUsed    uint8
	Algorithms uint64
}

func (r *DeviceInfoResponse) Parse(b []byte) error {
	if len(b) < 9 {
		return errInvalidLength
	}

	r.Version = fmt.Sprintf("%d.%d.%d", b[0], b[1], b[2])
	Parse32(b, 3, &r.Serial)
	r.LogTotal = b[7]
	r.LogUsed = b[8]
	r.Algorithms = 0
	for _, a := range b[9:] {
		if a >= algorithmMax {
			return errUnsupportedAlgorithm
		}
		r.Algorithms |= 1 << a
	}

	return nil
}

type GetPublicKeyCommand struct {
	KeyID ObjectID
}

func (*GetPublicKeyCommand) ID() CommandID {
	return CommandGetPublicKey
}

func (g *GetPublicKeyCommand) Serialize(out []byte) []byte {
	out = makeCmd(out, g, 2)
	return Append16(out, g.KeyID)
}

type GetPublicKeyResponse struct {
	PublicKey interface{ Equal(x crypto.PublicKey) bool }
}

//nolint:cyclop
func (g *GetPublicKeyResponse) Parse(b []byte) error {
	if len(b) < 1 {
		return errInvalidLength
	}

	a := AlgorithmID(b[0])
	b = b[1:]

	//nolint:exhaustive
	switch a {
	case AlgorithmED25519:
		if len(b) != ed25519.PublicKeySize {
			return errInvalidEd25519
		}
		g.PublicKey = ed25519.PublicKey(b)
		return nil

	case AlgorithmRSA2048:
		return g.parsePublicKeyRSA(b, 2048/8)
	case AlgorithmRSA3072:
		return g.parsePublicKeyRSA(b, 3072/8)
	case AlgorithmRSA4096:
		return g.parsePublicKeyRSA(b, 4096/8)

	case AlgorithmECP224:
		return g.parsePublicKeyECDSA(b, elliptic.P224())
	case AlgorithmECP256:
		return g.parsePublicKeyECDSA(b, elliptic.P256())
	case AlgorithmECP384:
		return g.parsePublicKeyECDSA(b, elliptic.P384())
	case AlgorithmECP521:
		return g.parsePublicKeyECDSA(b, elliptic.P521())

	default:
		return Errorf("unsupported public key algorithm: %v", a)
	}
}

func (g *GetPublicKeyResponse) parsePublicKeyRSA(b []byte, bytes int) error {
	if len(b) != bytes {
		return errInvalidRSA
	}

	var n big.Int
	n.SetBytes(b)
	g.PublicKey = &rsa.PublicKey{
		N: &n,
		E: 65537,
	}

	return nil
}

func (g *GetPublicKeyResponse) parsePublicKeyECDSA(b []byte, curve elliptic.Curve) error {
	var x, y big.Int
	x.SetBytes(b[:len(b)/2])
	y.SetBytes(b[len(b)/2:])
	if !curve.IsOnCurve(&x, &y) {
		return errInvalidECDSA
	}

	g.PublicKey = &ecdsa.PublicKey{
		Curve: curve,
		X:     &x,
		Y:     &y,
	}

	return nil
}

type ListObjectsFilter func([]byte) []byte

type ListObjectsCommand []ListObjectsFilter

// https://developers.yubico.com/YubiHSM2/Commands/List_Objects.html
const (
	filterID           = iota + 1 // 2 bytes
	filterType                    // 1 byte
	filterDomains                 // 2 bytes
	filterCapabilities            // 8 bytes
	filterAlgorithm               // 1 byte
	filterLabel                   // 40 bytes
)

func TypeFilter(typeID TypeID) ListObjectsFilter {
	return func(b []byte) []byte {
		return append(b, filterType, byte(typeID))
	}
}

func LabelFilter(label string) ListObjectsFilter {
	return func(b []byte) []byte {
		// Labels are padded and limited to 40 bytes
		var f [1 + 40]byte
		l := len(b)
		b = Append(b, f[:])
		b[l] = filterLabel
		copy(b[l+1:], label)
		return b
	}
}

func (l ListObjectsCommand) ID() CommandID {
	return CommandListObjects
}

func (l ListObjectsCommand) Serialize(out []byte) []byte {
	list := makeCmd(out, l, 0)
	for _, filter := range l {
		list = filter(list)
	}

	Put16(list[len(out)+1:], len(list)-len(out)-HeaderLength)
	return list
}

type listObjectsResponse struct {
	Object   ObjectID
	Type     TypeID
	Sequence uint8
}

type ListObjectsResponse []listObjectsResponse

func (l *ListObjectsResponse) Parse(b []byte) error {
	// 2 byte Object ID, 1 byte Type, 1 byte Sequence
	*l = make(ListObjectsResponse, len(b)/4)

	for i := range *l {
		object := &(*l)[i]
		Parse16(b, 0, &object.Object)
		Parse8(b, 2, &object.Type)
		Parse8(b, 3, &object.Sequence)
		b = b[4:]
	}

	if len(b) != 0 {
		return errTrailingBytes
	}
	return nil
}

type SignECDSACommand struct {
	KeyID  ObjectID
	Digest []byte
}

func (s *SignECDSACommand) ID() CommandID {
	return CommandSignECDSA
}

func (s *SignECDSACommand) Serialize(out []byte) []byte {
	return makeObjectDataCmd(out, s, s.KeyID, s.Digest)
}

type SignEdDSACommand struct {
	KeyID   ObjectID
	Message []byte
}

func (s *SignEdDSACommand) ID() CommandID {
	return CommandSignEdDSA
}

func (s *SignEdDSACommand) Serialize(out []byte) []byte {
	return makeObjectDataCmd(out, s, s.KeyID, s.Message)
}

type SignPKCS1v15Command struct {
	KeyID  ObjectID
	Digest []byte
}

func (s *SignPKCS1v15Command) ID() CommandID {
	return CommandSignPKCS1v15
}

func (s *SignPKCS1v15Command) Serialize(out []byte) []byte {
	return makeObjectDataCmd(out, s, s.KeyID, s.Digest)
}

type SignPSSCommand struct {
	KeyID   ObjectID
	MGF1    crypto.Hash
	SaltLen uint16
	Digest  []byte
}

func (s *SignPSSCommand) ID() CommandID {
	return CommandSignPSS
}

func (s *SignPSSCommand) Serialize(out []byte) []byte {
	out = makeCmd(out, s, 2+1+2+len(s.Digest))
	out = Append16(out, s.KeyID)
	out = Append8(out, Mgf1AlgorithmID(s.MGF1))
	out = Append16(out, s.SaltLen)
	return Append(out, s.Digest)
}

type SignResponse = sliceResponse

type DecryptPKCS1v15Command struct {
	KeyID      ObjectID
	CipherText []byte
}

func (d *DecryptPKCS1v15Command) ID() CommandID {
	return CommandDecryptPKCS1v15
}

func (d *DecryptPKCS1v15Command) Serialize(out []byte) []byte {
	return makeObjectDataCmd(out, d, d.KeyID, d.CipherText)
}

type DecryptOAEPCommand struct {
	KeyID      ObjectID
	MGF1       crypto.Hash
	LabelHash  crypto.Hash
	CipherText []byte
	Label      []byte
}

func (d *DecryptOAEPCommand) ID() CommandID {
	return CommandDecryptOAEP
}

func (d *DecryptOAEPCommand) Serialize(out []byte) []byte {
	digest := d.LabelHash.New()
	_, _ = digest.Write(d.Label)

	out = makeCmd(out, d, 2+1+len(d.CipherText)+digest.Size())
	out = Append16(out, d.KeyID)
	out = Append8(out, Mgf1AlgorithmID(d.MGF1))
	out = Append(out, d.CipherText)
	return digest.Sum(out)
}

type DecryptResponse = sliceResponse
