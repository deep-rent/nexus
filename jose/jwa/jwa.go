package jwa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"hash"
	"math/big"
	"sync"

	"github.com/cloudflare/circl/sign/ed448"
)

type Scheme[K crypto.PublicKey] interface {
	Name() string
	Type() string
	Verify(key K, msg, sig []byte) bool
}

type rsScheme struct {
	name string
	hash crypto.Hash
	pool sync.Pool
}

func newRSScheme(name string, hash crypto.Hash) Scheme[*rsa.PublicKey] {
	return &rsScheme{
		name: name,
		hash: hash,
		pool: sync.Pool{
			New: func() any {
				return hash.New()
			},
		},
	}
}

func (s *rsScheme) Name() string { return s.name }
func (s *rsScheme) Type() string { return "RSA" }

func (s *rsScheme) Verify(key *rsa.PublicKey, msg, sig []byte) bool {
	h := s.pool.Get().(hash.Hash)
	defer func() {
		h.Reset()
		s.pool.Put(h)
	}()
	h.Write(msg)
	digest := h.Sum(nil)
	return rsa.VerifyPKCS1v15(key, s.hash, digest, sig) == nil
}

var RS256 = newRSScheme("RS256", crypto.SHA256)
var RS384 = newRSScheme("RS384", crypto.SHA384)
var RS512 = newRSScheme("RS512", crypto.SHA512)

type psScheme struct {
	name string
	hash crypto.Hash
	pool sync.Pool
}

func (s *psScheme) Name() string { return s.name }
func (s *psScheme) Type() string { return "RSA" }

func (s *psScheme) Verify(key *rsa.PublicKey, msg, sig []byte) bool {
	h := s.pool.Get().(hash.Hash)
	defer func() {
		h.Reset()
		s.pool.Put(h)
	}()
	h.Write(msg)
	digest := h.Sum(nil)
	return rsa.VerifyPSS(key, s.hash, digest, sig, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	}) == nil
}

func newPSScheme(name string, hash crypto.Hash) Scheme[*rsa.PublicKey] {
	return &psScheme{
		name: name,
		hash: hash,
		pool: sync.Pool{
			New: func() any {
				return hash.New()
			},
		},
	}
}

var PS256 = newPSScheme("PS256", crypto.SHA256)
var PS384 = newPSScheme("PS384", crypto.SHA384)
var PS512 = newPSScheme("PS512", crypto.SHA512)

type esScheme struct {
	name string
	pool sync.Pool
}

func (s *esScheme) Name() string { return s.name }
func (s *esScheme) Type() string { return "EC" }

func (a *esScheme) Verify(key *ecdsa.PublicKey, msg, sig []byte) bool {
	n := (key.Curve.Params().BitSize + 7) / 8

	if len(sig) != 2*n {
		return false
	}

	r := new(big.Int).SetBytes(sig[:n])
	s := new(big.Int).SetBytes(sig[n:])

	h := a.pool.Get().(hash.Hash)
	defer func() {
		h.Reset()
		a.pool.Put(h)
	}()
	h.Write(msg)
	digest := h.Sum(nil)
	return ecdsa.Verify(key, digest, r, s)
}

func newESScheme(name string, hash crypto.Hash) Scheme[*ecdsa.PublicKey] {
	return &esScheme{
		name: name,
		pool: sync.Pool{
			New: func() any {
				return hash.New()
			},
		}}
}

var ES256 = newESScheme("ES256", crypto.SHA256)
var ES384 = newESScheme("ES384", crypto.SHA384)
var ES512 = newESScheme("ES512", crypto.SHA512)

type ed25519Scheme struct{}

func (s ed25519Scheme) Name() string { return "EdDSA" }
func (s ed25519Scheme) Type() string { return "OKP" }

func (s ed25519Scheme) Verify(key ed25519.PublicKey, msg, sig []byte) bool {
	return ed25519.Verify(key, msg, sig)
}

var Ed25519 Scheme[ed25519.PublicKey] = ed25519Scheme{}

type ed448Scheme struct{}

func (s ed448Scheme) Name() string { return "EdDSA" }
func (s ed448Scheme) Type() string { return "OKP" }

func (s ed448Scheme) Verify(key ed448.PublicKey, msg, sig []byte) bool {
	return ed448.Verify(key, msg, sig, "")
}

var Ed448 Scheme[ed448.PublicKey] = ed448Scheme{}

type Verifier interface {
	Algorithm() string
	Verify(msg, sig []byte) bool
}

type verifier[K crypto.PublicKey] struct {
	Scheme Scheme[K]
	Key    K
}

func (v verifier[K]) Algorithm() string { return v.Scheme.Name() }
func (v verifier[K]) Verify(msg, sig []byte) bool {
	return v.Scheme.Verify(v.Key, msg, sig)
}

func NewVerifier[K crypto.PublicKey](scheme Scheme[K], key K) Verifier {
	return verifier[K]{Scheme: scheme, Key: key}
}
