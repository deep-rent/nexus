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
	"crypto/rand"
	"crypto/sha3"
	"errors"
	"fmt"

	"crypto/mldsa"

	sign "github.com/deep-rent/nexus/sec/sign"
)

// ml implements the ML-DSA family of algorithms defined in FIPS 204.
type ml struct {
	// name is the JWA identifier.
	name string
	// params is the fixed ML-DSA parameter set.
	params mldsa.Parameters
}

// newML creates a new [Algorithm] for ML-DSA signatures with the given JWA
// name and parameter set.
func newML(name string, params mldsa.Parameters) Algorithm[*mldsa.PublicKey] {
	return &ml{
		name:   name,
		params: params,
	}
}

// Verify checks an ML-DSA signature. It rejects keys whose parameter set does
// not match the algorithm to prevent parameter set confusion.
func (a *ml) Verify(key *mldsa.PublicKey, msg, sig []byte) bool {
	if key.Parameters() != a.params {
		return false
	}
	return mldsa.Verify(key, msg, sig, nil) == nil
}

// Sign creates an ML-DSA signature using the provided signer.
//
// The message is not forwarded verbatim: it is pre-hashed into the 64-byte
// μ representative defined in FIPS 204 (external-μ mode, RFC 9881) and
// passed to the signer with [crypto.MLDSAMu]. The resulting signature is
// identical to signing the message directly in "pure" mode with an empty
// context string, as required by the JOSE registration, but remote signers
// (e.g., KMS or HSM backends) receive a constant-size input regardless of
// the message length. The signer's public key must be an [*mldsa.PublicKey]
// whose parameter set matches the algorithm.
func (a *ml) Sign(
	ctx context.Context,
	s sign.Signer,
	msg []byte,
) ([]byte, error) {
	pub, ok := s.Public().(*mldsa.PublicKey)
	if !ok {
		return nil, errors.New("signer public key is not ML-DSA")
	}
	if pub.Parameters() != a.params {
		return nil, fmt.Errorf(
			"signer parameter set %s does not match algorithm %s",
			pub.Parameters(), a.name,
		)
	}
	return s.Sign(ctx, rand.Reader, mu(pub, msg), crypto.MLDSAMu)
}

// mu computes the pre-hashed message representative μ as defined in FIPS 204
// for "pure" ML-DSA with an empty context string:
//
//	tr = SHAKE256(pk, 64)
//	μ  = SHAKE256(tr || 0x00 || 0x00 || msg, 64)
func mu(pub *mldsa.PublicKey, msg []byte) []byte {
	h := sha3.NewSHAKE256()
	h.Write(sha3.SumSHAKE256(pub.Bytes(), 64))
	// Domain separator (0 = pure ML-DSA) and empty context string length.
	h.Write([]byte{0, 0})
	h.Write(msg)
	out := make([]byte, 64)
	h.Read(out)
	return out
}

// Generate creates a new ML-DSA key pair.
func (a *ml) Generate() (crypto.Signer, error) {
	return mldsa.GenerateKey(a.params)
}

// String returns the JWA algorithm name.
func (a *ml) String() string {
	return a.name
}

// MLDSA44 represents the ML-DSA-44 signature algorithm (FIPS 204).
var MLDSA44 = newML("ML-DSA-44", mldsa.MLDSA44())

// MLDSA65 represents the ML-DSA-65 signature algorithm (FIPS 204).
var MLDSA65 = newML("ML-DSA-65", mldsa.MLDSA65())

// MLDSA87 represents the ML-DSA-87 signature algorithm (FIPS 204).
var MLDSA87 = newML("ML-DSA-87", mldsa.MLDSA87())
