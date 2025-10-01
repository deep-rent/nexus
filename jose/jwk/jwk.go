package jwk

import (
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

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/deep-rent/nexus/jose/jwa"
)

// Ref represents a reference to a Key. It
type Ref interface {
	// Algorithm returns the algorithm ("alg") the key must be used with.
	// This parameter is optional in the specification, but mandatory here.
	Algorithm() string
	// KeyID returns the unique id ("kid") for the key.
	// This parameter is optional in the specification, but mandatory here.
	KeyID() string
}

// Key represents a public JSON Web Key (JWK) used for signature verification.
type Key interface {
	Ref

	// Verify checks a signature against a message using the key material
	// and the associated algorithm.
	Verify(msg, sig []byte) bool
}

var ErrIneligibleKey = errors.New("ineligible for signature verification")

func Parse(in []byte) (Key, error) {
	var raw raw
	if err := json.Unmarshal(in, &raw); err != nil {
		return nil, fmt.Errorf("invalid json format: %w", err)
	}
	if raw.Kty == "" {
		return nil, errors.New("missing required parameter 'kty' (key type)")
	}
	if raw.Use != "sig" && !slices.Contains(raw.Ops, "verify") {
		return nil, ErrIneligibleKey
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

type key[T crypto.PublicKey] struct {
	alg jwa.Algorithm[T]
	kid string
	mat T
}

func (k *key[T]) Algorithm() string           { return k.alg.String() }
func (k *key[T]) KeyID() string               { return k.kid }
func (k *key[T]) Verify(msg, sig []byte) bool { return k.alg.Verify(k.mat, msg, sig) }

// Set represents a JSON Web Key Set (JWKS).
// A Set consists of zero or more Keys, each uniquely identified by a key id.
type Set interface {
	// Keys returns an iterator over all keys in the set.
	Keys() iter.Seq[Key]
	// Len returns the number of keys in this set.
	Len() int
	// Find looks up a key by its reference.
	// It returns nil if no matching key is found. Both, the key id and
	// the algorithm must match.
	Find(ref Ref) Key
}

type set map[string]Key

func (s set) Keys() iter.Seq[Key] { return maps.Values(s) }
func (s set) Len() int            { return len(s) }

func (s set) Find(ref Ref) Key {
	if ref == nil || ref.KeyID() == "" {
		return nil
	}
	k := s[ref.KeyID()]
	if k == nil || k.Algorithm() != ref.Algorithm() {
		return nil
	}
	return k
}

type emptySet struct{}

func (e emptySet) Keys() iter.Seq[Key] { return func(func(Key) bool) {} }
func (e emptySet) Len() int            { return 0 }
func (e emptySet) Find(ref Ref) Key    { return nil }

var empty Set = emptySet{}

// Parse parses a Set from the provided JSON input.
// If the input is severely malformed, an empty set along with an error is
// returned. If some keys are invalid, duplicated, or unsupported, they are
// skipped and the returned error describes the individual issues.
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
			// Skip unusable keys silently.
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

type raw struct {
	Kty string         `json:"kty"`
	Use string         `json:"use"`
	Ops []string       `json:"key_ops"`
	Alg string         `json:"alg"`
	Kid string         `json:"kid"`
	Mat jsontext.Value `json:",unknown"`
}

func (r *raw) Material(v any) error {
	if err := json.Unmarshal(r.Mat, v); err != nil {
		return fmt.Errorf("unmarshal %s key material: %w", r.Kty, err)
	}
	return nil
}

type loader func(r *raw) (Key, error)

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

func addLoader[T crypto.PublicKey](alg jwa.Algorithm[T], dec decoder[T]) {
	loaders[alg.String()] = func(r *raw) (Key, error) {
		mat, err := dec(r)
		if err != nil {
			return nil, err
		}
		kid := r.Kid
		return &key[T]{
			alg: alg,
			kid: kid,
			mat: mat,
		}, nil
	}
}

type decoder[T crypto.PublicKey] func(*raw) (T, error)

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
		return nil, fmt.Errorf("got length %d for %s curve, want %d", m, mat.Crv, n)
	}
	return mat.X, nil
}
