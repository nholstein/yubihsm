// Package yubihsm provides to a YubiHSM2 via idiomatic Go [crypto] APIs
//
// The YubiHSM2 is the big-sibling to the YubiKey PIV dongle. See [What
// is YubiHSM 2] for Yubico's documentation on their HSM.
//
// # Connecting to a YubiHSM2
//
// This package does not directly provide access to a YubiHSM2. Instead,
// you must run a separate _connector_ to provide access via USB. The
// most common option is Yubico's [yubihsm-connector]. This can either
// installed via source, your distribution's packages, or via Yubico's
// [yubihsm2-sdk].
//
// Alternatives to the yubihsm-connector include the [yubihsm.rs] example
// HTTP connector or its mockhsm.
//
// Each connector provides a simple HTTP POST interface to the YubiHSM2,
// providing binary a command-response interface. The connector listens
// at localhost:12345 by default, but it is possible to connect to a
// remote instance of the connector:
//
//	conn := NewHTTPConnector(WithConnectorURL("http://1.2.3.4:5678/connector/api"))
//
// # YubiHSM2 Sessions
//
// All meaningful commands on a YubiHSM2 are sent within the context of
// a [YubiHSM2 session]. Each session is encrypted and authenticated via
// a symmetric authentication key.
//
// An out-of-box YubiHSM2 is configured with a default authentication key
// derived from the password "password". You _must_ replace the default
// password and set a random key prior to using the HSM!
//
// Up to 16 sessions may be active concurrently on the HSM. Each session
// has a 30-second inactivity timeout before the session expires. This
// package does not currently support keepalives; long-running processes
// should implement this via the [Session.Ping] method:
//
//	var session Session
//	timer := time.NewTimer(20*time.Second)
//	for _ := range timer.C {
//		_, err := session.Echo(ctx, conn, 0xff)
//		if err != nil {
//			return err
//		}
//	}
//
// # YubiHSM2 Keys
//
// Keys can be loaded from a [Session]. This package currently does not
// support generating the keys, you can use an external tool such as
// [yubihsm-shell] instead.
//
// The returned key object generally conforms the standard [crypto] key
// APIs, and can be used wherever a [crypto.Signer] or [crypto.Deriver]
// is used.
//
// # Supported key algorithms
//
// Only asymmetric key pairs (RSA, ECDSA, Ed25519) are supported. Any of
// these may be used to generate a signature. Only an RSA key can be used
// to decrypt a message.
//
// Ed25519ph is not supported by the YubiHSM2, only plain Ed25519 works.
//
// ECDH is not supported. (The [crypto/ecdh] API is closed from external
// extension; there is no way to implement a [crypto/ecdh.PrivateKey] in
// a third-party module.)
//
// # Links
//
// [YubiHSM2 session]: https://developers.yubico.com/YubiHSM2/Concepts/Session.html
// [yubihsm-connector]: https://github.com/Yubico/yubihsm-connector/
// [yubihsm-shell]: https://github.com/Yubico/yubihsm-shell/
// [yubihsm2-sdk]: https://developers.yubico.com/YubiHSM2/Releases/
// [yubihsm.rs]: https://crates.io/crates/yubihsm
//
// [What is YubiHSM2]: https://developers.yubico.com/YubiHSM2/
package yubihsm

// checkErr squelches a return value if an error is given.
func checkErr[V any](value V, err error) (V, error) { //nolint:ireturn
	if err != nil {
		var zero V
		return zero, err
	}
	return value, nil
}
