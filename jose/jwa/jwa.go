// Package jwa provides implementations for JSON Web Algorithms (JWA)
// as defined in RFC 7518. It focuses on the computation and verification of
// signatures from asymmetric algorithms. This package includes support for
// RSASSA-PKCS1-v1_5 (RSxxx), RSASSA-PSS (PSxxx), ECDSA (ESxxx), and EdDSA
// algorithms, covering commonly used curves and hash functions. It lays the
// foundation for higher-level packages that deal with JSON Web Tokens (JWT) and
// JSON Web Keys (JWK).
package jwa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"hash"
	"math/big"
	"sync"

	"github.com/cloudflare/circl/sign/ed448"
)

// Algorithm represents an asymmetric JSON Web Algorithm (JWA) used for
// computing and verifying digitalsignatures. The type parameter T specifies
// the type of public key that the algorithm works with, while U specifies the
// corresponding type of private key.
type Algorithm[T crypto.PublicKey, U crypto.PrivateKey] interface {
	// fmt.Stringer provides the standard JWA name for the algorithm.
	fmt.Stringer

	// Verify checks a signature against a message using the provided public key.
	// It returns true if the signature is valid, and false otherwise. None of the
	// parameters must be nil, or else the call will panic.
	Verify(key T, msg, sig []byte) bool

	// Sign calculates a signature for a message using the provided private key.
	// It returns the computed signature or an error if signing fails. None of the
	// parameters must be nil, or else the call will panic.
	Sign(key U, msg []byte) ([]byte, error)

	// Generate creates a new public/private key pair suitable for use with
	// this algorithm. It returns the generated public key, private key, or an
	// error if key generation fails. If the algorithm offers degrees of freedom
	// in choosing domain parameters (e.g., key size), it should use sensible
	// defaults that provide adequate security.
	Generate() (T, U, error)
}

// rs implements the RSASSA-PKCS1-v1_5 family of algorithms (RSxxx).
type rs struct {
	name string
	pool *hashPool
	size int
}

// newRS creates a new Algorithm for RSASSA-PKCS1-v1_5 signatures
// with the given JWA name, hash function, and key size in bits.
func newRS(name string, hash crypto.Hash, size int) Algorithm[
	*rsa.PublicKey, *rsa.PrivateKey,
] {
	return &rs{
		name: name,
		pool: newHashPool(hash),
		size: size,
	}
}

func (a *rs) Verify(key *rsa.PublicKey, msg, sig []byte) bool {
	h := a.pool.Get()
	defer func() { a.pool.Put(h) }()
	h.Write(msg)
	digest := h.Sum(nil)
	return rsa.VerifyPKCS1v15(key, a.pool.Hash, digest, sig) == nil
}

func (a *rs) Sign(key *rsa.PrivateKey, msg []byte) ([]byte, error) {
	h := a.pool.Get()
	defer func() { a.pool.Put(h) }()
	h.Write(msg)
	digest := h.Sum(nil)
	return rsa.SignPKCS1v15(nil, key, a.pool.Hash, digest)
}

func (a *rs) Generate() (*rsa.PublicKey, *rsa.PrivateKey, error) {
	prv, err := rsa.GenerateKey(rand.Reader, a.size)
	if err != nil {
		return nil, nil, err
	}
	return &prv.PublicKey, prv, nil
}

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
	name string
	pool *hashPool
	size int
}

// newPS creates a new Algorithm for RSASSA-PSS signatures
// with the given JWA name, hash function, and key size in bits.
func newPS(name string, hash crypto.Hash, size int) Algorithm[
	*rsa.PublicKey, *rsa.PrivateKey,
] {
	return &ps{
		name: name,
		pool: newHashPool(hash),
		size: size,
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

func (a *ps) Sign(key *rsa.PrivateKey, msg []byte) ([]byte, error) {
	h := a.pool.Get()
	defer func() { a.pool.Put(h) }()
	h.Write(msg)
	digest := h.Sum(nil)
	// The salt length is set to match the hash size.
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
	return rsa.SignPSS(nil, key, a.pool.Hash, digest, opts)
}

func (a *ps) Generate() (*rsa.PublicKey, *rsa.PrivateKey, error) {
	prv, err := rsa.GenerateKey(rand.Reader, a.size)
	if err != nil {
		return nil, nil, err
	}
	return &prv.PublicKey, prv, nil
}

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
	name string
	pool *hashPool
	crv  elliptic.Curve
}

// newES creates a new Algorithm for ECDSA signatures
// with the given JWA name, hash function, and curve.
func newES(name string, hash crypto.Hash, crv elliptic.Curve) Algorithm[
	*ecdsa.PublicKey, *ecdsa.PrivateKey,
] {
	return &es{
		name: name,
		pool: newHashPool(hash),
		crv:  crv,
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

func (a *es) Sign(key *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	h := a.pool.Get()
	defer func() { a.pool.Put(h) }()
	h.Write(msg)
	digest := h.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		return nil, err
	}

	// Concatenate the fixed-size R and S (padded to 2n bytes).
	n := (key.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*n)
	r.FillBytes(sig[:n])
	s.FillBytes(sig[n:])
	return sig, nil
}

func (a *es) Generate() (*ecdsa.PublicKey, *ecdsa.PrivateKey, error) {
	prv, err := ecdsa.GenerateKey(a.crv, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return &prv.PublicKey, prv, nil
}

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

func (a *ed) Verify(key []byte, msg, sig []byte) bool {
	switch len(key) {
	case ed448.PublicKeySize:
		// Per RFC 8037, the JWS "EdDSA" algorithm corresponds to the "pure" EdDSA
		// variant, which uses an empty string for the context parameter.
		return ed448.Verify(ed448.PublicKey(key), msg, sig, "")
	case ed25519.PublicKeySize:
		return ed25519.Verify(ed25519.PublicKey(key), msg, sig)
	default:
		return false
	}
}

func (a *ed) Sign(key []byte, msg []byte) ([]byte, error) {
	switch len(key) {
	case ed448.PrivateKeySize:
		prv := ed448.PrivateKey(key)
		sig := ed448.Sign(prv, msg, "")
		return sig, nil
	case ed25519.PrivateKeySize:
		prv := ed25519.PrivateKey(key)
		sig := ed25519.Sign(prv, msg)
		return sig, nil
	default:
		return nil, fmt.Errorf("unsupported EdDSA private key size: %d", len(key))
	}
}

func (a *ed) Generate() ([]byte, []byte, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func (a *ed) String() string {
	return "EdDSA"
}

// EdDSA represents the EdDSA signature algorithm. It supports both Ed25519
// and Ed448 curves. The curve is determined by the size of the public key.
var EdDSA Algorithm[[]byte, []byte] = &ed{}

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
