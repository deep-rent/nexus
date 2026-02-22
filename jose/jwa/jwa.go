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

// Package jwa provides implementations for asymmetric JSON Web Algorithms
// (JWA) as defined in RFC 7518.
//
// It provides a unified interface for signature verification using public
// keys and signature creation using crypto.Signer. This abstraction handles
// algorithm-specific complexities such as hash function selection, padding
// schemes (e.g., PSS vs PKCS1v15), and signature format transcoding (e.g.,
// converting ECDSA ASN.1 DER to raw concatenation).
//
// Note: Symmetric algorithms (such as HMAC) are not supported.
package jwa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"sync"

	"github.com/cloudflare/circl/sign/ed448"
)

// Algorithm represents an asymmetric JSON Web Algorithm (JWA) used for
// verifying and calculating signatures. The type parameter T specifies the type
// of public key that the algorithm works with.
type Algorithm[T crypto.PublicKey] interface {
	// fmt.Stringer provides the standard JWA name for the algorithm.
	fmt.Stringer

	// Verify checks a signature against a message using the provided public key.
	// It returns true if the signature is valid, and false otherwise.
	// None of the parameters may be nil.
	Verify(key T, msg, sig []byte) bool

	// Sign creates a signature for the message using the provided signer.
	// The signer must be capable of using the algorithm's specific hash
	// and padding scheme.
	Sign(signer crypto.Signer, msg []byte) ([]byte, error)
}

// rs implements the RSASSA-PKCS1-v1_5 family of algorithms (RSxxx).
type rs struct {
	name string
	pool *hashPool
}

// newRS creates a new Algorithm for RSASSA-PKCS1-v1_5 signatures
// with the given JWA name and hash function.
func newRS(name string, hash crypto.Hash) Algorithm[*rsa.PublicKey] {
	return &rs{
		name: name,
		pool: newHashPool(hash),
	}
}

func (a *rs) Verify(key *rsa.PublicKey, msg, sig []byte) bool {
	h := a.pool.Get()
	defer func() { a.pool.Put(h) }()
	h.Write(msg)
	digest := h.Sum(nil)
	return rsa.VerifyPKCS1v15(key, a.pool.Hash, digest, sig) == nil
}

func (a *rs) Sign(signer crypto.Signer, msg []byte) ([]byte, error) {
	h := a.pool.Get()
	defer a.pool.Put(h)
	h.Write(msg)
	digest := h.Sum(nil)
	return signer.Sign(rand.Reader, digest, a.pool.Hash)
}

func (a *rs) String() string {
	return a.name
}

// RS256 represents the RSASSA-PKCS1-v1_5 signature algorithm using SHA-256.
var RS256 = newRS("RS256", crypto.SHA256)

// RS384 represents the RSASSA-PKCS1-v1_5 signature algorithm using SHA-384.
var RS384 = newRS("RS384", crypto.SHA384)

// RS512 represents the RSASSA-PKCS1-v1_5 signature algorithm using SHA-512.
var RS512 = newRS("RS512", crypto.SHA512)

// ps implements the RSASSA-PSS family of algorithms (PSxxx).
type ps struct {
	name string
	pool *hashPool
}

// newPS creates a new Algorithm for RSASSA-PSS signatures
// with the given JWA name and hash function.
func newPS(name string, hash crypto.Hash) Algorithm[*rsa.PublicKey] {
	return &ps{
		name: name,
		pool: newHashPool(hash),
	}
}

func (a *ps) Verify(key *rsa.PublicKey, msg, sig []byte) bool {
	h := a.pool.Get()
	defer func() { a.pool.Put(h) }()
	h.Write(msg)
	digest := h.Sum(nil)
	// The salt length is set to match the hash size.
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
	return rsa.VerifyPSS(key, a.pool.Hash, digest, sig, opts) == nil
}

func (a *ps) Sign(signer crypto.Signer, msg []byte) ([]byte, error) {
	h := a.pool.Get()
	defer a.pool.Put(h)
	h.Write(msg)
	digest := h.Sum(nil)
	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       a.pool.Hash,
	}
	return signer.Sign(rand.Reader, digest, opts)
}

func (a *ps) String() string {
	return a.name
}

// PS256 represents the RSASSA-PSS signature algorithm using SHA-256.
var PS256 = newPS("PS256", crypto.SHA256)

// PS384 represents the RSASSA-PSS signature algorithm using SHA-384.
var PS384 = newPS("PS384", crypto.SHA384)

// PS512 represents the RSASSA-PSS signature algorithm using SHA-512.
var PS512 = newPS("PS512", crypto.SHA512)

// es implements the ECDSA family of algorithms (ESxxx).
type es struct {
	name string
	pool *hashPool
}

// newES creates a new Algorithm for ECDSA signatures
// with the given JWA name and hash function.
func newES(name string, hash crypto.Hash) Algorithm[*ecdsa.PublicKey] {
	return &es{
		name: name,
		pool: newHashPool(hash),
	}
}

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

func (a *es) Sign(signer crypto.Signer, msg []byte) ([]byte, error) {
	h := a.pool.Get()
	defer a.pool.Put(h)
	h.Write(msg)
	digest := h.Sum(nil)
	der, err := signer.Sign(rand.Reader, digest, nil)
	if err != nil {
		return nil, err
	}
	var concat struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &concat); err != nil {
		return nil, fmt.Errorf("failed to parse ECDSA signature: %w", err)
	}

	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("signer public key is not ECDSA")
	}

	n := (pub.Curve.Params().BitSize + 7) / 8
	out := make([]byte, 2*n)
	concat.R.FillBytes(out[:n])
	concat.S.FillBytes(out[n:])

	return out, nil
}

func (a *es) String() string {
	return a.name
}

// ES256 represents the ECDSA signature algorithm using P-256 and SHA-256.
var ES256 = newES("ES256", crypto.SHA256)

// ES384 represents the ECDSA signature algorithm using P-384 and SHA-384.
var ES384 = newES("ES384", crypto.SHA384)

// ES512 represents the ECDSA signature algorithm using P-521 and SHA-512.
var ES512 = newES("ES512", crypto.SHA512)

// ed implements the EdDSA family of algorithms.
type ed struct{}

func (a *ed) Verify(key []byte, msg, sig []byte) bool {
	switch len(key) {
	case ed448.PublicKeySize:
		// Per RFC 8037, the JWS "EdDSA" algorithm corresponds to the "pure" EdDSA
		// variant, which uses an empty string for the context parameter.
		pub := ed448.PublicKey(key)
		return ed448.Verify(pub, msg, sig, "")
	case ed25519.PublicKeySize:
		pub := ed25519.PublicKey(key)
		return ed25519.Verify(pub, msg, sig)
	default:
		return false
	}
}

func (a *ed) Sign(signer crypto.Signer, msg []byte) ([]byte, error) {
	return signer.Sign(rand.Reader, msg, crypto.Hash(0))
}

func (a *ed) String() string {
	return "EdDSA"
}

// EdDSA represents the EdDSA signature algorithm. It supports both Ed25519
// and Ed448 curves. The curve is determined by the size of the public key.
var EdDSA Algorithm[[]byte] = &ed{}

// hashPool manages a pool of hash.Hash objects to reduce allocations.
type hashPool struct {
	Hash crypto.Hash
	pool *sync.Pool
}

// newHashPool creates a new hashPool for the given hash function.
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

// Get retrieves a hash.Hash from the pool.
func (p *hashPool) Get() hash.Hash {
	h := p.pool.Get()
	return h.(hash.Hash)
}

// Put returns a hash.Hash to the pool after resetting it.
func (p *hashPool) Put(h hash.Hash) {
	h.Reset()
	p.pool.Put(h)
}
