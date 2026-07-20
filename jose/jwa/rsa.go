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
	"crypto/rsa"

	sign "github.com/deep-rent/nexus/sign"
)

// rs implements the RSASSA-PKCS1-v1_5 family of algorithms (RSxxx).
type rs struct {
	// name is the JWA identifier.
	name string
	// pool is the internal hash pool for thread-safe operations.
	pool *hashPool
	// size is the generated key size in bits.
	size int
}

// newRS creates a new [Algorithm] for RSASSA-PKCS1-v1_5 signatures
// with the given JWA name and hash function.
func newRS(name string, hash crypto.Hash, size int) Algorithm[*rsa.PublicKey] {
	return &rs{
		name: name,
		pool: newHashPool(hash),
		size: size,
	}
}

// Verify checks an RSASSA-PKCS1-v1_5 signature.
func (a *rs) Verify(key *rsa.PublicKey, msg, sig []byte) bool {
	h := a.pool.Get()
	defer func() { a.pool.Put(h) }()
	h.Write(msg)
	digest := h.Sum(nil)
	return rsa.VerifyPKCS1v15(key, a.pool.Hash, digest, sig) == nil
}

// Sign creates an RSASSA-PKCS1-v1_5 signature using the provided signer.
func (a *rs) Sign(
	ctx context.Context,
	s sign.Signer,
	msg []byte,
) ([]byte, error) {
	h := a.pool.Get()
	defer a.pool.Put(h)
	h.Write(msg)
	digest := h.Sum(nil)
	return s.Sign(ctx, rand.Reader, digest, a.pool.Hash)
}

func (a *rs) Generate() (crypto.Signer, error) {
	return rsa.GenerateKey(rand.Reader, a.size)
}

// String returns the JWA algorithm name.
func (a *rs) String() string {
	return a.name
}

// RS256 represents the RSASSA-PKCS1-v1_5 signature algorithm using SHA-256.
var RS256 = newRS("RS256", crypto.SHA256, 3072)

// RS384 represents the RSASSA-PKCS1-v1_5 signature algorithm using SHA-384.
var RS384 = newRS("RS384", crypto.SHA384, 3072)

// RS512 represents the RSASSA-PKCS1-v1_5 signature algorithm using SHA-512.
var RS512 = newRS("RS512", crypto.SHA512, 4096)

// ps implements the RSASSA-PSS family of algorithms (PSxxx).
type ps struct {
	// name is the JWA identifier.
	name string
	// pool is the internal hash pool for thread-safe operations.
	pool *hashPool
	// size is the generated key size in bits.
	size int
}

// newPS creates a new [Algorithm] for RSASSA-PSS signatures
// with the given JWA name and hash function.
func newPS(name string, hash crypto.Hash, size int) Algorithm[*rsa.PublicKey] {
	return &ps{
		name: name,
		pool: newHashPool(hash),
		size: size,
	}
}

// Verify checks an RSASSA-PSS signature.
func (a *ps) Verify(key *rsa.PublicKey, msg, sig []byte) bool {
	h := a.pool.Get()
	defer func() { a.pool.Put(h) }()
	h.Write(msg)
	digest := h.Sum(nil)
	// The salt length is set to match the hash size.
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
	return rsa.VerifyPSS(key, a.pool.Hash, digest, sig, opts) == nil
}

// Sign creates an RSASSA-PSS signature using the provided signer.
func (a *ps) Sign(
	ctx context.Context,
	s sign.Signer,
	msg []byte,
) ([]byte, error) {
	h := a.pool.Get()
	defer a.pool.Put(h)
	h.Write(msg)
	digest := h.Sum(nil)
	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       a.pool.Hash,
	}
	return s.Sign(ctx, rand.Reader, digest, opts)
}

// Generate creates a new RSA key pair.
func (a *ps) Generate() (crypto.Signer, error) {
	return rsa.GenerateKey(rand.Reader, a.size)
}

// String returns the JWA algorithm name.
func (a *ps) String() string {
	return a.name
}

// PS256 represents the RSASSA-PSS signature algorithm using SHA-256.
var PS256 = newPS("PS256", crypto.SHA256, 3072)

// PS384 represents the RSASSA-PSS signature algorithm using SHA-384.
var PS384 = newPS("PS384", crypto.SHA384, 3072)

// PS512 represents the RSASSA-PSS signature algorithm using SHA-512.
var PS512 = newPS("PS512", crypto.SHA512, 4096)
