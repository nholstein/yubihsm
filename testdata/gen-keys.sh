#!/bin/sh

# A simple script to generate key data on the yubihsm.rs mockhsm.

set -ex

function cleanup() {
	rm $RSA2048 $RSA3072 $RSA4096
}

trap cleanup exit

# The yubihsm.rs mockhsm doesn't support generating RSA keys; instead use
# OpenSSL to generate temporaries.

RSA2048=`mktemp rsa-2048.pem.XXXXXXXX`
RSA3072=`mktemp rsa-3072.pem.XXXXXXXX`
RSA4096=`mktemp rsa-4096.pem.XXXXXXXX`

openssl genrsa 2048 >$RSA2048
openssl genrsa 3072 >$RSA3072
openssl genrsa 4096 >$RSA4096

# The yubihsm.rs mockhsm doesn't support generating random key IDs, so
# pregenerate a key "random" ones.

yubihsm-shell <<-HSM
	connect
	session open 1 password
	put asymmetric 0 0xc4f1 test-rsa2048 1 sign-pss,sign-pkcs,decrypt-oaep,decrypt-pkcs $RSA2048
	put asymmetric 0 0x459b test-rsa3072 1 sign-pss,sign-pkcs,decrypt-oaep,decrypt-pkcs $RSA3072
	put asymmetric 0 0x49d6 test-rsa4096 1 sign-pss,sign-pkcs,decrypt-oaep,decrypt-pkcs $RSA4096
	generate asymmetric 0 0x8aba p256 1 sign-ecdsa ecp256
	generate asymmetric 0 0x621d test-key 1 sign-eddsa ed25519
	session close 0
HSM
