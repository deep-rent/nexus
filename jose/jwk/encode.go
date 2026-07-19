// Copyright (c) 2025-present deep.rent GmbH (https://deep.rent)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/sign"
)

// writers maps a JWA algorithm name to the function responsible for encoding
// its key material.
var writers map[string]writer

// writer defines a function that encodes the key material into a marshallable
// JWT struct.
type writer func(mat any, r *raw) error

// pairer defines a function that binds a [sign.Signer] to a registered
// algorithm, producing a [KeyPair]. It returns nil if the signer's public key
// type does not match the algorithm.
type pairer func(kid string, s sign.Signer) KeyPair

// pairers maps a JWA algorithm name to the function responsible for building
// key pairs.
var pairers map[string]pairer

// register wires up an algorithm's decoding, encoding, and key pair
// construction in a type-safe manner. Every supported algorithm must be
// registered exactly once in init.
func register[T crypto.PublicKey](
	alg jwa.Algorithm[T],
	dec decoder[T],
	enc encoder[T],
) {
	name := alg.String()
	readers[name] = func(r *raw) (Key, error) {
		mat, err := dec(r)
		if err != nil {
			return nil, err
		}
		return NewKey(alg, r.Kid, mat), nil
	}
	writers[name] = func(mat any, r *raw) error {
		pub, ok := mat.(T)
		if !ok {
			return fmt.Errorf("invalid key for algorithm %q", name)
		}
		return enc(pub, r)
	}
	pairers[name] = func(kid string, s sign.Signer) KeyPair {
		return NewKeyPair(alg, kid, s)
	}
}

// encoder defines a function that populates the [raw] JWK parameters from the
// algorithm-specific key material.
type encoder[T crypto.PublicKey] func(mat T, r *raw) error

// encodeRSA populates the RSA-specific fields ("n", "e") in the [raw] JWK.
func encodeRSA(key *rsa.PublicKey, r *raw) error {
	r.Kty = "RSA"
	r.N = base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := key.E
	if e == 0 {
		return errors.New("RSA public exponent is zero")
	}
	var eBytes []byte
	if e < 0xFFFFFF {
		eBytes = make([]byte, 0, 3)
	} else {
		eBytes = make([]byte, 0, 4)
	}

	for e > 0 {
		eBytes = append([]byte{byte(e)}, eBytes...)
		e >>= 8
	}
	r.E = base64.RawURLEncoding.EncodeToString(eBytes)
	return nil
}

// encodeECDSA populates the ECDSA-specific fields ("crv", "x", "y").
// It enforces fixed-width padding for coordinates as required by RFC 7518.
func encodeECDSA(key *ecdsa.PublicKey, r *raw) error {
	r.Kty = "EC"
	params := key.Params()
	r.Crv = params.Name

	// Obtain the SEC 1 uncompressed format: 0x04 || X || Y.
	b, err := key.Bytes()
	if err != nil {
		return fmt.Errorf("encode ecdsa key: %w", err)
	}

	if len(b) < 1 || b[0] != 4 {
		return errors.New("invalid public key format")
	}

	// Calculate coordinate size dynamically based on the returned slice.
	size := (len(b) - 1) / 2
	x := b[1 : 1+size]
	y := b[1+size : 1+(2*size)]

	r.X = base64.RawURLEncoding.EncodeToString(x)
	r.Y = base64.RawURLEncoding.EncodeToString(y)
	return nil
}

// encodeEdDSA populates the EdDSA-specific fields ("crv", "x").
// It determines the curve name based on the key length.
func encodeEdDSA(key ed25519.PublicKey, r *raw) error {
	r.Kty = "OKP"

	if len(key) == ed25519.PublicKeySize {
		r.Crv = "Ed25519"
	} else {
		return fmt.Errorf("invalid EdDSA key length: %d", len(key))
	}

	r.X = base64.RawURLEncoding.EncodeToString(key)
	return nil
}

// encodeMLDSA populates the ML-DSA-specific field ("pub"). The key type
// "AKP" (Algorithm Key Pair) is defined in draft-ietf-cose-dilithium.
func encodeMLDSA(key *mldsa.PublicKey, r *raw) error {
	r.Kty = "AKP"
	r.Pub = base64.RawURLEncoding.EncodeToString(key.Bytes())
	return nil
}

// init registers all supported algorithms.
func init() {
	const size = 13

	readers = make(map[string]reader, size)
	writers = make(map[string]writer, size)
	pairers = make(map[string]pairer, size)

	register(jwa.RS256, decodeRSA, encodeRSA)
	register(jwa.RS384, decodeRSA, encodeRSA)
	register(jwa.RS512, decodeRSA, encodeRSA)
	register(jwa.PS256, decodeRSA, encodeRSA)
	register(jwa.PS384, decodeRSA, encodeRSA)
	register(jwa.PS512, decodeRSA, encodeRSA)
	register(jwa.ES256, decodeECDSA(elliptic.P256()), encodeECDSA)
	register(jwa.ES384, decodeECDSA(elliptic.P384()), encodeECDSA)
	register(jwa.ES512, decodeECDSA(elliptic.P521()), encodeECDSA)
	register(jwa.EdDSA, decodeEdDSA, encodeEdDSA)
	register(jwa.MLDSA44, decodeMLDSA(mldsa.MLDSA44()), encodeMLDSA)
	register(jwa.MLDSA65, decodeMLDSA(mldsa.MLDSA65()), encodeMLDSA)
	register(jwa.MLDSA87, decodeMLDSA(mldsa.MLDSA87()), encodeMLDSA)
}
