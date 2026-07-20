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

package jwa

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/deep-rent/nexus/sign"
)

// es implements the ECDSA family of algorithms (ESxxx).
type es struct {
	// name is the JWA identifier.
	name string
	// pool is the internal hash pool for thread-safe operations.
	pool *hashPool
	// ecrv is the elliptic curve.
	ecrv elliptic.Curve
}

// newES creates a new [Algorithm] for ECDSA signatures
// with the given JWA name and hash function.
func newES(
	name string,
	hash crypto.Hash,
	ecrv elliptic.Curve,
) Algorithm[*ecdsa.PublicKey] {
	return &es{
		name: name,
		pool: newHashPool(hash),
		ecrv: ecrv,
	}
}

// Verify checks an ECDSA signature.
func (a *es) Verify(key *ecdsa.PublicKey, msg, sig []byte) bool {
	// The signature is the concatenation of two integers of the same size
	// as the curve's order.
	n := (key.Curve.Params().BitSize + 7) / 8
	if len(sig) != 2*n {
		return false
	}
	h := a.pool.Get()
	defer func() { a.pool.Put(h) }()
	h.Write(msg)
	digest := h.Sum(nil)

	// Split the signature into R and S.
	r := new(big.Int).SetBytes(sig[:n])
	s := new(big.Int).SetBytes(sig[n:])

	return ecdsa.Verify(key, digest, r, s)
}

// Sign creates an ECDSA signature and transcodes it from ASN.1 DER to raw
// format.
func (a *es) Sign(
	ctx context.Context,
	s sign.Signer,
	msg []byte,
) ([]byte, error) {
	h := a.pool.Get()
	defer a.pool.Put(h)
	h.Write(msg)
	digest := h.Sum(nil)

	der, err := s.Sign(ctx, rand.Reader, digest, nil)
	if err != nil {
		return nil, err
	}
	var concat struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &concat); err != nil {
		return nil, fmt.Errorf("failed to parse ECDSA signature: %w", err)
	}

	pub, ok := s.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("signer public key is not ECDSA")
	}

	n := (pub.Curve.Params().BitSize + 7) / 8
	if (concat.R.BitLen()+7)/8 > n || (concat.S.BitLen()+7)/8 > n {
		return nil, errors.New(
			"ECDSA signature values R or S are too large for the curve size",
		)
	}

	out := make([]byte, 2*n)
	concat.R.FillBytes(out[:n])
	concat.S.FillBytes(out[n:])

	return out, nil
}

// Generate creates a new ECDSA key pair.
func (a *es) Generate() (crypto.Signer, error) {
	return ecdsa.GenerateKey(a.ecrv, rand.Reader)
}

// String returns the JWA algorithm name.
func (a *es) String() string {
	return a.name
}

// ES256 represents the ECDSA signature algorithm using P-256 and SHA-256.
var ES256 = newES("ES256", crypto.SHA256, elliptic.P256())

// ES384 represents the ECDSA signature algorithm using P-384 and SHA-384.
var ES384 = newES("ES384", crypto.SHA384, elliptic.P384())

// ES512 represents the ECDSA signature algorithm using P-521 and SHA-512.
var ES512 = newES("ES512", crypto.SHA512, elliptic.P521())
