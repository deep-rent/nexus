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

// Package jwa provides implementations for asymmetric JSON Web Algorithms.
//
// Package jwa provides implementations for asymmetric JSON Web Algorithms (JWA)
// as defined in RFC 7518, as well as the post-quantum ML-DSA signature scheme
// (FIPS 204) registered for JOSE in draft-ietf-cose-dilithium. It provides a
// unified interface for signature verification using public keys and signature
// creation using [signer.Signer]. This abstraction handles algorithm-specific
// complexities such as hash function selection, padding schemes (e.g., PSS vs
// PKCS1v15), and signature format transcoding (e.g., converting ECDSA ASN.1
// DER to raw concatenation).
//
// Note: Symmetric algorithms (such as HMAC) are not supported.
//
// # ML-DSA
//
// The ML-DSA algorithms ([MLDSA44], [MLDSA65], [MLDSA87]) implement the
// post-quantum signature scheme specified in FIPS 204, using the JOSE
// registrations from draft-ietf-cose-dilithium ("AKP" key type). Two
// practical caveats apply:
//
// FIPS mode: the ML-DSA algorithms are unavailable when the FIPS 140-3 Go
// Cryptographic Module v1.0.0 is selected (via the GODEBUG fips140
// setting); every key generation, signing, and verification operation then
// fails at runtime. Module version v1.26.0 or later is required.
//
// Token size: ML-DSA signatures are large (2420, 3309, and 4627 bytes for
// ML-DSA-44, -65, and -87 respectively), so a signed JWT weighs in at
// roughly 3.3 to 6.3 KB after base64url encoding. Such tokens exceed the
// typical 4 KB cookie limit and may exceed default HTTP header size limits
// of reverse proxies. Prefer ML-DSA-44 where token size matters, and avoid
// storing ML-DSA tokens in cookies.
//
// # Usage
//
// This package is typically used to verify or sign JWS payloads by selecting
// a specific [Algorithm] instance like [RS256] or [EdDSA].
//
// Example:
//
//	// Verify a signature using RS256
//	valid := jwa.RS256.Verify(publicKey, message, signature)
package jwa

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha3"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"sync"

	"crypto/mldsa"

	sign "github.com/deep-rent/nexus/sign"
)

// Algorithm represents an asymmetric JSON Web Algorithm (JWA) used for
// verifying and calculating signatures. The type parameter T specifies the type
// of public key that the algorithm works with.
type Algorithm[T crypto.PublicKey] interface {
	// Verify checks a signature against a message with the provided public key.
	// It returns true if the signature is valid, and false otherwise.
	// None of the parameters may be nil.
	Verify(key T, msg, sig []byte) bool

	// Sign creates a signature for the message using the provided signer.
	// The signer must be capable of using the algorithm's specific hash
	// and padding scheme. If the signer implements signer.Signer, the
	// context will be propagated.
	Sign(ctx context.Context, s sign.Signer, msg []byte) ([]byte, error)

	// Generate randomly generates a new public/private key pair with
	// recommended parameters for the algorithm. It returns an error if the
	// generation fails.
	Generate() (crypto.Signer, error)

	// String provides the standard JWA name for the algorithm.
	String() string
}

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

// ed implements the EdDSA family of algorithms.
type ed struct{}

// Verify checks an EdDSA signature, supporting Ed25519.
func (a *ed) Verify(key ed25519.PublicKey, msg, sig []byte) bool {
	return ed25519.Verify(key, msg, sig)
}

// Sign creates an EdDSA signature using the provided signer.
func (a *ed) Sign(
	ctx context.Context,
	s sign.Signer,
	msg []byte,
) ([]byte, error) {
	return s.Sign(ctx, rand.Reader, msg, crypto.Hash(0))
}

// Generate creates a new Ed25519 key pair.
func (a *ed) Generate() (crypto.Signer, error) {
	_, prv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return prv, nil
}

// String returns the JWA algorithm name.
func (a *ed) String() string {
	return "EdDSA"
}

// EdDSA represents the EdDSA signature algorithm. It supports the Ed25519
// curve.
var EdDSA Algorithm[ed25519.PublicKey] = &ed{}

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

// hashPool manages a pool of [hash.Hash] objects to reduce allocations.
type hashPool struct {
	// Hash is the underlying hash identifier.
	Hash crypto.Hash
	// pool is the [sync.Pool] containing initialized [hash.Hash] instances.
	pool *sync.Pool
}

// newHashPool creates a new [hashPool] for the given hash function.
func newHashPool(hash crypto.Hash) *hashPool {
	pool := &sync.Pool{
		New: func() any {
			return hash.New()
		},
	}
	return &hashPool{
		Hash: hash,
		pool: pool,
	}
}

// Get retrieves a [hash.Hash] from the pool.
func (p *hashPool) Get() hash.Hash {
	h := p.pool.Get()
	return h.(hash.Hash)
}

// Put returns a [hash.Hash] to the pool after resetting it.
func (p *hashPool) Put(h hash.Hash) {
	h.Reset()
	p.pool.Put(h)
}
