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
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/deep-rent/nexus/jose/jwa"
)

// reader defines a function that decodes the key material from a [raw] JWK
// and constructs a concrete [Key].
type reader func(r *raw) (Key, error)

// readers maps a JWA algorithm name to the function responsible for parsing
// its key material.
var readers map[string]reader

// addReader helps populate the readers map in a type-safe manner.
func addReader[T crypto.PublicKey](alg jwa.Algorithm[T], dec decoder[T]) {
	readers[alg.String()] = func(r *raw) (Key, error) {
		mat, err := dec(r)
		if err != nil {
			return nil, err
		}
		return NewKey(alg, r.Kid, mat), nil
	}
}

// decoder decodes the key material for a specific key type T.
type decoder[T crypto.PublicKey] func(*raw) (T, error)

// decodeRSA parses the material for an RSA public key.
func decodeRSA(raw *raw) (*rsa.PublicKey, error) {
	if raw.Kty != "RSA" {
		return nil, fmt.Errorf("incompatible key type %q", raw.Kty)
	}
	if len(raw.N) == 0 {
		return nil, errors.New("missing modulus")
	}
	if len(raw.E) == 0 {
		return nil, errors.New("missing public exponent")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(raw.N)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(raw.E)
	if err != nil {
		return nil, fmt.Errorf("decode public exponent: %w", err)
	}
	// Exponents > 2^31-1 are extremely rare and not recommended.
	if len(eBytes) > 4 {
		return nil, errors.New("public exponent exceeds 32 bits")
	}
	n := new(big.Int).SetBytes(nBytes)
	e := 0
	// The conversion to a big-endian unsigned integer is safe because of the
	// length check above.
	for _, b := range eBytes {
		e = (e << 8) | int(b)
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

// decodeECDSA creates a [decoder] for the specified elliptic curve.
func decodeECDSA(crv elliptic.Curve) decoder[*ecdsa.PublicKey] {
	return func(raw *raw) (*ecdsa.PublicKey, error) {
		if raw.Kty != "EC" {
			return nil, fmt.Errorf("incompatible key type %q", raw.Kty)
		}
		if raw.Crv != crv.Params().Name {
			return nil, fmt.Errorf("incompatible curve %q", raw.Crv)
		}
		if len(raw.X) == 0 {
			return nil, errors.New("missing x coordinate")
		}
		if len(raw.Y) == 0 {
			return nil, errors.New("missing y coordinate")
		}

		xBytes, err := base64.RawURLEncoding.DecodeString(raw.X)
		if err != nil {
			return nil, fmt.Errorf("decode x coordinate: %w", err)
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(raw.Y)
		if err != nil {
			return nil, fmt.Errorf("decode y coordinate: %w", err)
		}

		// Calculate the required byte size for the curve coordinates.
		size := (crv.Params().BitSize + 7) / 8
		if len(xBytes) > size || len(yBytes) > size {
			return nil, errors.New("coordinate length exceeds curve size")
		}

		// Construct the SEC 1 uncompressed point format: 0x04 || X || Y.
		uncompressed := make([]byte, 1+(2*size))
		uncompressed[0] = 4
		copy(uncompressed[1+size-len(xBytes):1+size], xBytes)
		copy(uncompressed[1+(2*size)-len(yBytes):], yBytes)

		pub, err := ecdsa.ParseUncompressedPublicKey(crv, uncompressed)
		if err != nil {
			return nil, fmt.Errorf("parse public key: %w", err)
		}

		return pub, nil
	}
}

// decodeEdDSA parses the material for an EdDSA public key.
func decodeEdDSA(raw *raw) (ed25519.PublicKey, error) {
	if raw.Kty != "OKP" {
		return nil, fmt.Errorf("incompatible key type %q", raw.Kty)
	}
	if raw.Crv != "Ed25519" {
		return nil, fmt.Errorf("unsupported curve %q", raw.Crv)
	}
	n := ed25519.PublicKeySize
	x, err := base64.RawURLEncoding.DecodeString(raw.X)
	if err != nil {
		return nil, fmt.Errorf("decode x coordinate: %w", err)
	}
	if m := len(x); m != n {
		return nil, fmt.Errorf(
			"illegal key size for %s curve: got %d, want %d", raw.Crv, m, n,
		)
	}
	return x, nil
}
