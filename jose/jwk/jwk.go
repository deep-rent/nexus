// Package jwk provides functionality to parse and manage JSON Web Keys (JWK)
// and JSON Web Key Sets (JWKS), as defined in RFC 7517. It is specifically
// designed for the purpose of verifying JWT signatures.
//
// Keys that are not intended for signature verification (based on their "use"
// or "key_ops" parameters) are considered ineligible and will be ignored
// during parsing of a JWKS.
//
// This implementation deliberately deviates from the RFC for robustness and
// simplicity: the "alg" (algorithm) and "kid" (key id) parameters, both
// optional in the standard, are treated mandatory for all eligible keys.
package jwk

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"iter"
	"maps"
	"math/big"
	"slices"
	"time"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/deep-rent/nexus/cache"
	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/scheduler"
)

// Hint represents a reference to a Key, containing the minimum information
// needed to look one up in a Set. It effectively abstracts the JWS header
// fields ("alg" and "kid") used to select a key for signature verification.
type Hint interface {
	// Algorithm returns the algorithm ("alg") the key must be used with.
	Algorithm() string
	// KeyID returns the unique id ("kid") for the key.
	KeyID() string
}

// Key represents a public JSON Web Key (JWK) used for signature verification.
type Key interface {
	Hint

	// Verify checks a signature against a message using the key's material
	// and its associated algorithm. It returns true if the signature is valid.
	// It returns false if the signature is invalid or if any of the parameters
	// are nil.
	Verify(msg, sig []byte) bool
}

// New creates a new Key programmatically from its constituent parts. The type
// parameter T must match the public key type expected by the provided
// algorithm (e.g., *rsa.PublicKey for jwa.RS256).
func New[T crypto.PublicKey](alg jwa.Algorithm[T], kid string, mat T) Key {
	return &key[T]{alg: alg, kid: kid, mat: mat}
}

// key is a concrete implementation of the Key interface, generic over the
// public key type.
type key[T crypto.PublicKey] struct {
	alg jwa.Algorithm[T]
	kid string
	mat T // The actual cryptographic public key material.
}

func (k *key[T]) Algorithm() string { return k.alg.String() }
func (k *key[T]) KeyID() string     { return k.kid }

func (k *key[T]) Verify(msg, sig []byte) bool {
	if msg == nil || sig == nil {
		return false
	}
	return k.alg.Verify(k.mat, msg, sig)
}

// ErrIneligibleKey indicates that a key may be syntactically valid but should
// not be used for signature verification according to its "use" or "key_ops"
// parameters.
var ErrIneligibleKey = errors.New("ineligible for signature verification")

// Parse parses a single Key from the provided JSON input.
//
// It first checks if the key is eligible for signature verification. If not,
// it returns ErrIneligibleKey. Otherwise, it proceeds to validate the presence
// of required parameters ("kty", "kid", "alg"), the supported algorithm, and
// the integrity of the key material itself.
func Parse(in []byte) (Key, error) {
	var raw raw
	if err := json.Unmarshal(in, &raw); err != nil {
		return nil, fmt.Errorf("invalid json format: %w", err)
	}
	// Per RFC 7517, a key's purpose is determined by the union of "use" and
	// "key_ops". We perform this check first for efficiency, as we only care
	// about signature verification keys.
	if raw.Use != "sig" && !slices.Contains(raw.Ops, "verify") {
		return nil, ErrIneligibleKey
	}
	if raw.Kty == "" {
		return nil, errors.New("missing required parameter 'kty' (key type)")
	}
	if raw.Kid == "" {
		return nil, errors.New("missing required parameter 'kid' (key id)")
	}
	if raw.Alg == "" {
		return nil, errors.New("missing required parameter 'alg' (algorithm)")
	}
	load := loaders[raw.Alg]
	if load == nil {
		return nil, fmt.Errorf("unknown algorithm %q", raw.Alg)
	}
	key, err := load(&raw)
	if err != nil {
		return nil, fmt.Errorf("load %s material: %w", raw.Kty, err)
	}
	return key, nil
}

// Set stores an immutable collection of Keys, typically parsed from a JWKS.
// It provides efficient lookups of keys for signature verification.
type Set interface {
	// Keys returns an iterator over all keys in the set.
	Keys() iter.Seq[Key]
	// Len returns the number of keys in this set.
	Len() int
	// Find looks up a key using the specified hint. A key is returned only
	// if both its key id and algorithm match the hint exactly.
	// Otherwise, it returns nil.
	Find(hint Hint) Key
}

// NewSet creates a Set programmatically from the provided slice of Keys. Any
// nil keys in the input are filtered out. If multiple keys share the same
// key id, the last one in the slice wins.
func NewSet(keys ...Key) Set {
	s := make(set, len(keys))
	for _, k := range keys {
		if k != nil {
			s[k.KeyID()] = k
		}
	}
	return s
}

// set is the concrete implementation of the Set interface.
// It uses a map for efficient O(1) average time complexity lookups.
type set map[string]Key

func (s set) Keys() iter.Seq[Key] { return maps.Values(s) }
func (s set) Len() int            { return len(s) }

func (s set) Find(hint Hint) Key {
	if hint == nil || hint.KeyID() == "" {
		return nil
	}
	k := s[hint.KeyID()]
	if k == nil || k.Algorithm() != hint.Algorithm() {
		return nil
	}
	return k
}

type emptySet struct{}

func (e emptySet) Keys() iter.Seq[Key] { return func(func(Key) bool) {} }
func (e emptySet) Len() int            { return 0 }
func (e emptySet) Find(Hint) Key       { return nil }

// empty is a singleton instance of an empty Set.
var empty Set = emptySet{}

// ParseSet parses a Set from a JWKS JSON input.
//
// If the top-level JSON structure is malformed, it returns an empty set and
// a fatal error. Otherwise, it iterates through the "keys" array, parsing
// each key individually. Keys that are invalid, unsupported, or carry a
// duplicate key id, result in non-fatal errors. Ineligible keys (e.g., those
// meant for encryption) are silently skipped. If any non-fatal errors occurred,
// a joined error is returned alongside the set of successfully parsed keys.
func ParseSet(in []byte) (Set, error) {
	var raw struct {
		Keys []jsontext.Value `json:"keys"`
	}
	if err := json.Unmarshal(in, &raw); err != nil {
		return empty, fmt.Errorf("invalid format: %w", err)
	}
	s := make(set, len(raw.Keys))
	var errs []error
	for i, v := range raw.Keys {
		k, err := Parse(v)
		if err != nil {
			if errors.Is(err, ErrIneligibleKey) {
				continue
			}
			err = fmt.Errorf("key at index %d: %w", i, err)
			errs = append(errs, err)
			continue
		}
		kid := k.KeyID()
		if s[kid] != nil {
			err = fmt.Errorf("key at index %d: duplicate key id %q", i, kid)
			errs = append(errs, err)
			continue
		}
		s[kid] = k
	}
	return s, errors.Join(errs...)
}

// CacheSet extends the Set interface with scheduler.Tick, creating a component
// that can be deployed to a scheduler for automatic refreshing of a remote
// JWKS view in the background.
type CacheSet interface {
	Set
	scheduler.Tick
}

// cacheSet is the concrete implementation of the CacheSet interface.
type cacheSet struct {
	ctrl cache.Controller[Set]
}

// get safely retrieves the current Set from the cache controller. If the
// cache has not been populated yet (e.g., due to an initial network failure),
// it returns a static empty set to ensure that delegated operations like Find
// do not panic. This makes the Set resilient to transient startup issues.
func (s *cacheSet) get() Set {
	if set, ok := s.ctrl.Get(); ok {
		return set
	}
	return empty
}

func (s *cacheSet) Keys() iter.Seq[Key] { return s.get().Keys() }
func (s *cacheSet) Len() int            { return s.get().Len() }
func (s *cacheSet) Find(hint Hint) Key  { return s.get().Find(hint) }

func (s *cacheSet) Run(ctx context.Context) time.Duration {
	return s.ctrl.Run(ctx)
}

// mapper adapts the ParseSet function to the cache.Mapper interface.
var mapper cache.Mapper[Set] = func(in []byte) (Set, error) {
	return ParseSet(in)
}

// NewCacheSet creates a CacheSet that stays in sync with a remote JWKS
// endpoint. It must be deployed to a scheduler.Scheduler to begin the
// background fetching and refreshing process.
//
// The provided cache.Options can configure behaviors like refresh interval,
// request timeouts, and error handling.
func NewCacheSet(url string, opts ...cache.Option) CacheSet {
	ctrl := cache.NewController(url, mapper, opts...)
	return &cacheSet{ctrl}
}

// raw holds the JWK parameters.
type raw struct {
	Kty string         `json:"kty"`
	Use string         `json:"use"`
	Ops []string       `json:"key_ops"`
	Alg string         `json:"alg"`
	Kid string         `json:"kid"`
	Mat jsontext.Value `json:",unknown"` // Capture all other fields.
}

// Material allows deferred, type-safe unmarshaling of the key material itself
// into the provided struct pointer.
func (r *raw) Material(v any) error {
	if err := json.Unmarshal(r.Mat, v); err != nil {
		return fmt.Errorf("unmarshal %s key material: %w", r.Kty, err)
	}
	return nil
}

// loader defines a function that decodes the key material from a raw JWK
// and constructs a concrete Key.
type loader func(r *raw) (Key, error)

// loaders maps a JWA algorithm name to the function responsible for parsing
// its key material.
var loaders map[string]loader

func init() {
	loaders = make(map[string]loader, 10)
	addLoader(jwa.RS256, decodeRSA)
	addLoader(jwa.RS384, decodeRSA)
	addLoader(jwa.RS512, decodeRSA)
	addLoader(jwa.PS256, decodeRSA)
	addLoader(jwa.PS384, decodeRSA)
	addLoader(jwa.PS512, decodeRSA)
	addLoader(jwa.ES256, decodeECDSA(elliptic.P256()))
	addLoader(jwa.ES384, decodeECDSA(elliptic.P384()))
	addLoader(jwa.ES512, decodeECDSA(elliptic.P521()))
	addLoader(jwa.EdDSA, decodeEdDSA)
}

// addLoader helps populate the loaders map in a type-safe manner.
func addLoader[T crypto.PublicKey](alg jwa.Algorithm[T], dec decoder[T]) {
	loaders[alg.String()] = func(r *raw) (Key, error) {
		mat, err := dec(r)
		if err != nil {
			return nil, err
		}
		return New(alg, r.Kid, mat), nil
	}
}

// decoder decodes the key material for a specific key type T.
type decoder[T crypto.PublicKey] func(*raw) (T, error)

// decodeRSA parses the material for an RSA public key.
func decodeRSA(raw *raw) (*rsa.PublicKey, error) {
	if raw.Kty != "RSA" {
		return nil, fmt.Errorf("incompatible key type %q", raw.Kty)
	}
	var mat struct {
		N []byte `json:"n,format:base64url"`
		E []byte `json:"e,format:base64url"`
	}
	if err := raw.Material(&mat); err != nil {
		return nil, err
	}
	if len(mat.N) == 0 {
		return nil, errors.New("missing RSA modulus")
	}
	if len(mat.E) == 0 {
		return nil, errors.New("missing RSA public exponent")
	}
	// Exponents > 2^31-1 are extremely rare and not recommended.
	if len(mat.E) > 4 {
		return nil, errors.New("RSA public exponent exceeds 32 bits")
	}
	n := new(big.Int).SetBytes(mat.N)
	e := 0
	// The conversion to a big-endian unsigned integer is safe because of the
	// length check above.
	for _, b := range mat.E {
		e = (e << 8) | int(b)
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

// decodeECDSA creates a decoder for the specified elliptic curve.
func decodeECDSA(crv elliptic.Curve) decoder[*ecdsa.PublicKey] {
	return func(raw *raw) (*ecdsa.PublicKey, error) {
		if raw.Kty != "EC" {
			return nil, fmt.Errorf("incompatible key type %q", raw.Kty)
		}
		var mat struct {
			Crv string `json:"crv"`
			X   []byte `json:"x,format:base64url"`
			Y   []byte `json:"y,format:base64url"`
		}
		if err := raw.Material(&mat); err != nil {
			return nil, err
		}
		if mat.Crv != crv.Params().Name {
			return nil, fmt.Errorf("incompatible curve %q", mat.Crv)
		}
		if len(mat.X) == 0 {
			return nil, errors.New("missing EC x coordinate")
		}
		if len(mat.Y) == 0 {
			return nil, errors.New("missing EC y coordinate")
		}
		x := new(big.Int).SetBytes(mat.X)
		y := new(big.Int).SetBytes(mat.Y)
		return &ecdsa.PublicKey{Curve: crv, X: x, Y: y}, nil
	}
}

// decodeEdDSA parses the material for an EdDSA public key.
func decodeEdDSA(raw *raw) ([]byte, error) {
	if raw.Kty != "OKP" {
		return nil, fmt.Errorf("incompatible key type %q", raw.Kty)
	}
	var mat struct {
		Crv string `json:"crv"`
		X   []byte `json:"x,format:base64url"`
	}
	if err := raw.Material(&mat); err != nil {
		return nil, err
	}
	var n int
	switch mat.Crv {
	case "Ed448":
		n = ed448.PublicKeySize
	case "Ed25519":
		n = ed25519.PublicKeySize
	default:
		return nil, fmt.Errorf("unsupported OKP curve %q", mat.Crv)
	}
	if m := len(mat.X); m != n {
		return nil, fmt.Errorf("illegal key size for %s curve: got %d, want %d",
			mat.Crv, m, n)
	}
	return mat.X, nil
}
