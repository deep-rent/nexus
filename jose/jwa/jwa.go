// Package jwa provides implementations for JSON Web Algorithms (JWA)
// as defined in RFC 7518. It focuses on the verification of signatures
// from asymmetric algorithms, whose public keys can be distributed
// via a JWKS (JSON Web Key Set) endpoint.
package jwa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"hash"
	"math/big"
	"sync"

	"github.com/cloudflare/circl/sign/ed448"
)

// Algorithm represents an asymmetric JSON Web Algorithm (JWA) used for
// verifying signatures. The type parameter T specifies the type of public key
// that the algorithm works with.
type Algorithm[T crypto.PublicKey] interface {
	// fmt.Stringer provides the standard JWA name for the algorithm.
	fmt.Stringer

	// Verify checks a signature against a message using the provided public key.
	// It returns true if the signature is valid, and false otherwise.
	// None of the parameters may be nil.
	Verify(key T, msg, sig []byte) bool
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
		// Per RFC 8037, the context for Ed448ph is empty.
		return ed448.Verify(ed448.PublicKey(key), msg, sig, "")
	case ed25519.PublicKeySize:
		return ed25519.Verify(ed25519.PublicKey(key), msg, sig)
	default:
		return false
	}
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
