package jwa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"math/big"

	"github.com/cloudflare/circl/sign/ed448"
)

type Scheme[K crypto.PublicKey] interface {
	Name() string
	Verify(key K, msg, sig []byte) bool
}

type rs struct {
	name string
	hash crypto.Hash
}

func (a rs) Name() string { return a.name }

func (a rs) Verify(key *rsa.PublicKey, msg, sig []byte) bool {
	h := a.hash.New()
	h.Write(msg)
	digest := h.Sum(nil)
	return rsa.VerifyPKCS1v15(key, a.hash, digest, sig) == nil
}

var _ Scheme[*rsa.PublicKey] = rs{}

var RS256 = rs{name: "RS256", hash: crypto.SHA256}
var RS384 = rs{name: "RS384", hash: crypto.SHA384}
var RS512 = rs{name: "RS512", hash: crypto.SHA512}

type ps struct {
	name string
	hash crypto.Hash
}

func (a ps) Name() string { return a.name }

func (a ps) Verify(key *rsa.PublicKey, msg, sig []byte) bool {
	h := a.hash.New()
	h.Write(msg)
	digest := h.Sum(nil)
	return rsa.VerifyPSS(key, a.hash, digest, sig, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	}) == nil
}

var _ Scheme[*rsa.PublicKey] = ps{}

var PS256 = ps{name: "PS256", hash: crypto.SHA256}
var PS384 = ps{name: "PS384", hash: crypto.SHA384}
var PS512 = ps{name: "PS512", hash: crypto.SHA512}

type es struct {
	name string
	hash crypto.Hash
	size int
}

func (a es) Name() string { return a.name }

func (a es) Verify(key *ecdsa.PublicKey, msg, sig []byte) bool {
	if len(sig) != 2*a.size {
		return false
	}

	r := new(big.Int).SetBytes(sig[:a.size])
	s := new(big.Int).SetBytes(sig[a.size:])

	h := a.hash.New()
	h.Write(msg)
	digest := h.Sum(nil)
	return ecdsa.Verify(key, digest, r, s)
}

var _ Scheme[*ecdsa.PublicKey] = es{}

var ES256 = es{name: "ES256", hash: crypto.SHA256, size: 32}
var ES384 = es{name: "ES384", hash: crypto.SHA384, size: 48}
var ES512 = es{name: "ES512", hash: crypto.SHA512, size: 66}

type ed1 struct{}

func (a ed1) Name() string { return "EdDSA" }

func (a ed1) Verify(key ed25519.PublicKey, msg, sig []byte) bool {
	return ed25519.Verify(key, msg, sig)
}

var _ Scheme[ed25519.PublicKey] = ed1{}

var Ed25519 = ed1{}

type ed2 struct{}

func (a ed2) Name() string { return "EdDSA" }

func (a ed2) Verify(key ed448.PublicKey, msg, sig []byte) bool {
	return ed448.Verify(key, msg, sig, "")
}

var _ Scheme[ed448.PublicKey] = ed2{}

var Ed448 = ed2{}

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
