// Package jwk provides functionality to parse and manage JSON Web Keys (JWK)
// and JSON Web Key Sets (JWKS), as defined in RFC 7517. It is specifically
// designed for the purpose of verifying JWT signatures. Hence, only public
// keys can be represented.
//
// # Eligible Keys
//
// Keys that are not intended for signature verification are considered
// ineligible and will be skipped during parsing of a JWKS. A key is eligible
// if it meets at least one of the following criteria:
//
//   - The "use" (Public Key Use) parameter is set to "sig".
//   - The "key_ops" (Key Operations) parameter includes "verify".
//
// # Key Selection
//
// This implementation deliberately deviates from the RFC for robustness and
// simplicity:
//
//  1. The "alg" (Algorithm) parameter, optional in the standard, is treated as
//     mandatory for all eligible keys. Enforcing this is a best practice that
//     mitigates algorithm confusion attacks.
//  2. For key selection, either "kid" (Key ID) or "x5t#S256" (SHA-256
//     Thumbprint) must be defined. The "x5t" (SHA-1 Thumbprint) parameter is
//     explicitly ignored as it is considered outdated. No other lookup
//     mechanism is supported.
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
	"math/big"
	"reflect"
	"slices"
	"time"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/deep-rent/nexus/cache"
	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/scheduler"
)

// Hint represents a reference to a Key, containing the minimum information
// needed to look one up in a Set. It effectively abstracts the JWS header
// fields used to select a key for signature verification.
type Hint interface {
	// Algorithm returns the JWA algorithm name that the key is intended for.
	// This must match the "alg" parameter in the JWS header.
	Algorithm() string
	// KeyID returns the unique identifier for the key, or an empty string if
	// absent. This must match the "kid" parameter in the JWS header.
	// One of "kid" or "x5t#S256" must be present. If both are present, "kid"
	// takes precedence during lookups.
	KeyID() string
	// Thumbprint returns the base64url-encoded SHA-256 digest of the DER-encoded
	// X.509 certificate associated with the key, or an empty string if absent.
	// This must match the "x5t#S256" parameter in the JWS header. One of "kid" or
	// "x5t#S256" must be present. If both are present, "kid" takes precedence
	// during lookups.
	Thumbprint() string
}

type hint[T crypto.PublicKey, U crypto.PrivateKey] struct {
	alg jwa.Algorithm[T, U]
	kid string
	x5t string
}

func (h *hint[T, U]) Algorithm() string  { return h.alg.String() }
func (h *hint[T, U]) KeyID() string      { return h.kid }
func (h *hint[T, U]) Thumbprint() string { return h.x5t }

func (h *hint[T, U]) setKid(kid string) { h.kid = kid }
func (h *hint[T, U]) setX5t(x5t string) { h.x5t = x5t }
func (h *hint[T, U]) isComplete() bool  { return h.kid != "" || h.x5t != "" }

type config interface {
	setKid(string)
	setX5t(string)
	isComplete() bool
}

type Option func(config)

func WithKid(kid string) Option {
	return func(c config) {
		c.setKid(kid)
	}
}

func WithX5t(x5t string) Option {
	return func(c config) {
		c.setX5t(x5t)
	}
}

// Key represents a public JSON Web Key (JWK) used for signature
// verification.
type Key interface {
	Hint
	json.Marshaler

	// Verify checks a signature against a message using the key's material
	// and its associated algorithm. It returns true if the signature is valid.
	// It returns false if the signature is invalid.
	Verify(msg, sig []byte) bool

	Sign(msg []byte) ([]byte, error)

	IsPair() bool

	Public() Key
}

// New creates a new Key programmatically from its constituent
// parts. The type parameters T and U must match the key types expected by the
// provided algorithm (e.g., *rsa.PublicKey and *rsa.PrivateKey for jwa.RS256).
// To create a public-only Key without private key material, pass nil for the
// prv parameter.
func New[T crypto.PublicKey, U crypto.PrivateKey](
	alg jwa.Algorithm[T, U],
	pub T,
	prv U,
	opts ...Option,
) Key {
	h := &hint[T, U]{alg: alg}
	for _, opt := range opts {
		opt(h)
	}
	if !h.isComplete() {
		panic("key must be identifiable")
	}
	return newKey(h, pub, prv)
}

func newKey[T crypto.PublicKey, U crypto.PrivateKey](
	h *hint[T, U],
	pub T,
	prv U,
) Key {
	rv := reflect.ValueOf(prv)
	var isPair bool
	switch rv.Kind() {
	case
		reflect.Pointer,
		reflect.Slice,
		reflect.Map,
		reflect.Func,
		reflect.Interface,
		reflect.Chan:
		isPair = !rv.IsNil()
	default:
		isPair = true
	}
	return &key[T, U]{hint: h, pub: pub, prv: prv, isPair: isPair}
}

// key is a concrete implementation of the Key interface, generic over the
// wrapped key types.
type key[T crypto.PublicKey, U crypto.PrivateKey] struct {
	*hint[T, U]

	// Actual cryptographic key material

	pub T
	prv U

	isPair bool
}

func (k *key[T, U]) Verify(msg, sig []byte) bool {
	return k.alg.Verify(k.pub, msg, sig)
}

func (k *key[T, U]) Sign(msg []byte) ([]byte, error) {
	if !k.isPair {
		return nil, errors.New("private key material is missing")
	}
	return k.alg.Sign(k.prv, msg)
}

func (k *key[T, U]) IsPair() bool { return k.isPair }

func (k *key[T, U]) Public() Key {
	if !k.isPair {
		return k
	} else {
		return &key[T, U]{hint: k.hint, pub: k.pub, isPair: false}
	}
}

func (k *key[T, U]) MarshalJSON() ([]byte, error) {
	raw := &raw{}
	codec := codecs[k.alg.String()]
	if codec == nil {
		return nil, fmt.Errorf("no codec for algorithm %q", k.alg.String())
	}
	if err := codec.encode(k, raw); err != nil {
		return nil, fmt.Errorf("encode key material: %w", err)
	}
	raw.Alg = k.alg.String()
	raw.Kid = k.KeyID()
	raw.X5t = k.Thumbprint()
	if k.isPair {
		raw.Ops = []string{"verify", "sign"}
	} else {
		raw.Use = "sig"
		raw.Ops = []string{"verify"}
	}
	return json.Marshal(raw)
}

func Generate[T crypto.PublicKey, U crypto.PrivateKey](
	alg jwa.Algorithm[T, U], opts ...Option,
) (Key, error) {
	pub, prv, err := alg.Generate()
	if err != nil {
		return nil, err
	}
	return New(alg, pub, prv, opts...), nil
}

// ErrIneligibleKey indicates that a key may be syntactically valid but should
// not be used for signature verification according to its "use" or "key_ops"
// parameters.
var ErrIneligibleKey = errors.New("ineligible for signature verification")

// Parse parses a single Key from the provided JSON input.
//
// It first checks if the key is eligible for signature verification. If not,
// it returns ErrIneligibleKey. Otherwise, it proceeds to validate the presence
// of required parameters ("kty" and "alg"), whether the algorithm is supported,
// and the integrity of the key material itself.
func Parse(in []byte) (Key, error) {
	var r raw
	if err := json.Unmarshal(in, &r); err != nil {
		return nil, fmt.Errorf("invalid json format: %w", err)
	}
	// Per RFC 7517, a key's purpose is determined by the union of "use" and
	// "key_ops". We perform this check first for efficiency, as we only care
	// about signature verification keys.
	eligible := false
	if len(r.Ops) != 0 {
		// If key_ops is present, it must contain "sign" or "verify".
		if slices.Contains(r.Ops, "verify") || slices.Contains(r.Ops, "sign") {
			eligible = true
		}
	} else if r.Use == "sig" {
		// If key_ops is missing, "use" must be "sig".
		eligible = true
	}
	if !eligible {
		return nil, ErrIneligibleKey
	}
	if r.Kty == "" {
		return nil, errors.New("undefined key type")
	}
	if r.Alg == "" {
		return nil, errors.New("algorithm not specified")
	}
	if r.Kid == "" && r.X5t == "" {
		return nil, errors.New("key must be identifiable")
	}
	codec := codecs[r.Alg]
	if codec == nil {
		return nil, fmt.Errorf("unknown algorithm %q", r.Alg)
	}
	key, err := codec.decode(&r)
	if err != nil {
		return nil, fmt.Errorf("load %s key material: %w", r.Kty, err)
	}
	return key, nil
}

// Set stores an immutable collection of Keys, typically parsed from a JWKS.
// It provides efficient lookups of keys for signature verification.
type Set interface {
	json.Marshaler

	// Keys returns an iterator over all keys in this set.
	Keys() iter.Seq[Key]
	// Len returns the number of keys in this set.
	Len() int
	// Find looks up a key using the specified hint. A key is returned only
	// if both its key id and algorithm match the hint exactly.
	// Otherwise, it returns nil.
	Find(hint Hint) Key
}

// newSet creates a new, empty Set with the specified initial capacity.
func newSet(n int) *set {
	return &set{
		keys: make([]Key, 0, n),
		kid:  make(map[string]int, n),
		x5t:  make(map[string]int, n),
	}
}

// set is the concrete implementation of the Set interface.
// It uses maps for efficient O(1) average time complexity lookups.
type set struct {
	keys []Key
	kid  map[string]int // Maps key id to index in keys array.
	x5t  map[string]int // Maps thumbprint to index in keys array.
}

func (s *set) Keys() iter.Seq[Key] { return slices.Values(s.keys) }
func (s *set) Len() int            { return len(s.keys) }

func (s *set) Find(hint Hint) Key {
	if hint == nil {
		return nil
	}
	var k Key
	if i, ok := s.kid[hint.KeyID()]; ok {
		k = s.keys[i]
	} else if i, ok := s.x5t[hint.Thumbprint()]; ok {
		k = s.keys[i]
	} else {
		return nil
	}
	if k.Algorithm() != hint.Algorithm() {
		return nil
	}
	return k
}

func (s *set) MarshalJSON() ([]byte, error) {
	var raw struct {
		Keys []jsontext.Value `json:"keys"`
	}
	n := len(s.keys)
	raw.Keys = make([]jsontext.Value, n)
	for i, k := range s.keys {
		data, err := k.Public().MarshalJSON()
		if err != nil {
			return nil, fmt.Errorf("marshal key at index %d: %w", i, err)
		}
		raw.Keys[i] = jsontext.Value(data)
	}
	return json.Marshal(raw)
}

var emptySetIterator = func(func(Key) bool) {}

type emptySet struct{}

func (e emptySet) Keys() iter.Seq[Key] { return emptySetIterator }
func (e emptySet) Len() int            { return 0 }
func (e emptySet) Find(Hint) Key       { return nil }

func (e emptySet) MarshalJSON() ([]byte, error) {
	return []byte(`{"keys":[]}`), nil
}

// empty is a singleton instance of an empty Set.
var empty Set = emptySet{}

// ParseSet parses a Set from a JWKS JSON input.
//
// If the top-level JSON structure is malformed, it returns an empty set and
// a fatal error. Otherwise, it iterates through the "keys" array, parsing
// each key individually. Keys that are invalid, unsupported, or occur multiple
// times, result in non-fatal errors. Ineligible keys (e.g., those meant for
// encryption) are silently skipped. If any non-fatal errors occurred, a joined
// error is returned alongside the set of successfully parsed keys.
func ParseSet(in []byte) (Set, error) {
	var raw struct {
		Keys []jsontext.Value `json:"keys"`
	}
	if err := json.Unmarshal(in, &raw); err != nil {
		return empty, fmt.Errorf("invalid format: %w", err)
	}
	n := len(raw.Keys)
	if n == 0 {
		return empty, nil
	}
	s := newSet(n)
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
		x5t := k.Thumbprint()
		if kid != "" {
			if _, ok := s.kid[kid]; ok {
				errs = append(errs, fmt.Errorf(
					"key at index %d: duplicate key id %q", i, kid,
				))
				continue // Skip this key
			}
		}
		if x5t != "" {
			if _, ok := s.x5t[x5t]; ok {
				errs = append(errs, fmt.Errorf(
					"key at index %d: duplicate thumbprint %q", i, x5t,
				))
				continue // Skip this key
			}
		}
		idx := len(s.keys)
		s.keys = append(s.keys, k)
		if kid != "" {
			s.kid[kid] = idx
		}
		if x5t != "" {
			s.x5t[x5t] = idx
		}
	}

	// Prune the slice to its actual length to free up unused capacity.
	s.keys = slices.Clip(s.keys)

	return s, errors.Join(errs...)
}

func NewSet(keys ...Key) (Set, error) {
	s := newSet(len(keys))
	for i, k := range keys {
		s.keys = append(s.keys, k)
		kid := k.KeyID()
		x5t := k.Thumbprint()
		if kid != "" {
			if _, ok := s.kid[kid]; ok {
				return nil, fmt.Errorf(
					"key at index %d: duplicate key id %q", i, kid,
				)
			}
		}
		if x5t != "" {
			if _, ok := s.x5t[x5t]; ok {
				return nil, fmt.Errorf(
					"key at index %d: duplicate thumbprint %q", i, x5t,
				)
			}
		}
		idx := len(s.keys)
		s.keys = append(s.keys, k)
		if kid != "" {
			s.kid[kid] = idx
		}
		if x5t != "" {
			s.x5t[x5t] = idx
		}
	}

	// Prune the slice to its actual length to free up unused capacity.
	s.keys = slices.Clip(s.keys)

	return s, nil
}

// CacheSet extends the Set interface with scheduler.Tick, creating a component
// that can be deployed to a scheduler for automatic refreshing of a remote
// JWKS view in the background. The default implementation is backed by a
// cache.Controller.
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

func (s *cacheSet) Keys() iter.Seq[Key]          { return s.get().Keys() }
func (s *cacheSet) Len() int                     { return s.get().Len() }
func (s *cacheSet) Find(hint Hint) Key           { return s.get().Find(hint) }
func (s *cacheSet) MarshalJSON() ([]byte, error) { return s.get().MarshalJSON() }

func (s *cacheSet) Run(ctx context.Context) time.Duration {
	return s.ctrl.Run(ctx)
}

// mapper adapts the ParseSet function to the cache.Mapper interface.
var mapper cache.Mapper[Set] = func(r *cache.Response) (Set, error) {
	set, err := ParseSet(r.Body)
	if set.Len() == 0 {
		return nil, errors.New("no valid keys found")
	}
	if err != nil {
		r.Logger.Debug("Some keys could not be parsed", "error", err)
	}
	// Don't complain unless there are no keys available at all.
	return set, nil
}

// NewCacheSet creates a new CacheSet that stays in sync with a remote JWKS
// endpoint. It must be deployed to a scheduler.Scheduler to begin the
// background fetching and refreshing process.
//
// The provided cache.Options can configure behaviors like refresh interval,
// request timeouts, and error handling. Parsing of retrieved key sets is
// extremely lenient: it will only fail if no valid keys are found at all.
func NewCacheSet(url string, opts ...cache.Option) CacheSet {
	ctrl := cache.NewController(url, mapper, opts...)
	return &cacheSet{ctrl}
}

// raw holds the JWK parameters.
type raw struct {
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	Ops []string `json:"key_ops"`
	Alg string   `json:"alg"`
	Kid string   `json:"kid,omitempty"`
	X5t string   `json:"x5t#S256,omitempty"`
	N   []byte   `json:"n,format:base64url,omitempty"`
	E   []byte   `json:"e,format:base64url,omitempty"`
	Crv string   `json:"crv,omitempty"`
	X   []byte   `json:"x,format:base64url,omitempty"`
	Y   []byte   `json:"y,format:base64url,omitempty"`
	D   []byte   `json:"d,format:base64url,omitempty"`
	P   []byte   `json:"p,format:base64url,omitempty"`
	Q   []byte   `json:"q,format:base64url,omitempty"`
	DP  []byte   `json:"dp,format:base64url,omitempty"`
	DQ  []byte   `json:"dq,format:base64url,omitempty"`
	QI  []byte   `json:"qi,format:base64url,omitempty"`
}

type codec struct {
	encode func(Key, *raw) error
	decode func(*raw) (Key, error)
}

var codecs map[string]*codec

func init() {
	codecs = make(map[string]*codec, 10)
	addRSACodec(jwa.RS256)
	addRSACodec(jwa.RS384)
	addRSACodec(jwa.RS512)
	addRSACodec(jwa.PS256)
	addRSACodec(jwa.PS384)
	addRSACodec(jwa.PS512)
	addECDSACodec(jwa.ES256, elliptic.P256())
	addECDSACodec(jwa.ES384, elliptic.P384())
	addECDSACodec(jwa.ES512, elliptic.P521())
	addCodec(jwa.EdDSA, encodeEdDSA, decodeEdDSA)
}

// addCodec populates the codecs map in a type-safe manner.
func addCodec[T crypto.PublicKey, U crypto.PrivateKey](
	alg jwa.Algorithm[T, U],
	enc encoder[T, U],
	dec decoder[T, U],
) {
	codecs[alg.String()] = &codec{
		encode: func(k Key, r *raw) error {
			switch t := k.(type) {
			case *key[T, U]:
				return enc(t.pub, t.prv, r)
			default:
				return fmt.Errorf("incompatible key type %T", k)
			}
		},
		decode: func(r *raw) (Key, error) {
			pub, prv, err := dec(r)
			if err != nil {
				return nil, err
			}
			h := &hint[T, U]{alg: alg, kid: r.Kid, x5t: r.X5t}
			return newKey(h, pub, prv), nil
		},
	}
}

func addRSACodec(
	alg jwa.Algorithm[*rsa.PublicKey, *rsa.PrivateKey],
) {
	addCodec(alg, encodeRSA, decodeRSA)
}

func addECDSACodec(
	alg jwa.Algorithm[*ecdsa.PublicKey, *ecdsa.PrivateKey],
	crv elliptic.Curve,
) {
	addCodec(alg, encodeECDSA(crv), decodeECDSA(crv))
}

// decoder decodes the key material for a specific key type T.
type decoder[T crypto.PublicKey, U crypto.PrivateKey] func(*raw) (T, U, error)

type encoder[T crypto.PublicKey, U crypto.PrivateKey] func(
	pub T, prv U, r *raw,
) error

// decodeRSA parses the material for an RSA key.
func decodeRSA(raw *raw) (*rsa.PublicKey, *rsa.PrivateKey, error) {
	if raw.Kty != "RSA" {
		return nil, nil, fmt.Errorf("incompatible key type %q", raw.Kty)
	}
	if len(raw.N) == 0 {
		return nil, nil, errors.New("missing modulus")
	}
	if len(raw.E) == 0 {
		return nil, nil, errors.New("missing public exponent")
	}
	// Exponents > 2^31-1 are extremely rare and not recommended.
	if len(raw.E) > 4 {
		return nil, nil, errors.New("public exponent exceeds 32 bits")
	}
	n := new(big.Int).SetBytes(raw.N)
	e := 0
	// The conversion to a big-endian unsigned integer is safe because of the
	// length check above.
	for _, b := range raw.E {
		e = (e << 8) | int(b)
	}
	pub := &rsa.PublicKey{N: n, E: e}
	if len(raw.D) == 0 {
		return pub, nil, nil
	}

	if len(raw.P) == 0 || len(raw.Q) == 0 {
		return nil, nil, errors.New("missing prime factor for private key")
	}

	prv := &rsa.PrivateKey{
		PublicKey: *pub,
		D:         new(big.Int).SetBytes(raw.D),
		Primes: []*big.Int{
			new(big.Int).SetBytes(raw.P),
			new(big.Int).SetBytes(raw.Q),
		},
	}

	if dp := raw.DP; len(dp) > 0 {
		prv.Precomputed.Dp = new(big.Int).SetBytes(dp)
	}
	if dq := raw.DQ; len(dq) > 0 {
		prv.Precomputed.Dq = new(big.Int).SetBytes(dq)
	}
	if qi := raw.QI; len(qi) > 0 {
		prv.Precomputed.Qinv = new(big.Int).SetBytes(qi)
	}

	if err := prv.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid private key: %w", err)
	}

	return pub, prv, nil
}

func encodeRSA(pub *rsa.PublicKey, prv *rsa.PrivateKey, raw *raw) error {
	raw.Kty = "RSA"
	// Match the 32-bit limit set enforced during decoding.
	if pub.E > 0xFFFFFFFF {
		return fmt.Errorf("public exponent %d exceeds 32 bits", pub.E)
	}
	raw.N = pub.N.Bytes()
	raw.E = big.NewInt(int64(pub.E)).Bytes()
	// Per RFC 7518 Sec 6.3.1.2, "e" must not be empty.
	// This handles the (unlikely) case of E = 0.
	if len(raw.E) == 0 {
		raw.E = []byte{0}
	}
	// Conditionally encode private parameters
	if prv != nil {
		raw.D = prv.D.Bytes()
		// Per RFC 7518, P and Q must be provided for private keys.
		if len(prv.Primes) != 2 {
			return errors.New("expected two primes (p and q)")
		}
		raw.P = prv.Primes[0].Bytes()
		raw.Q = prv.Primes[1].Bytes()

		// Other precomputed values are optional but recommended.
		if dp := prv.Precomputed.Dp; dp != nil {
			raw.DP = dp.Bytes()
		}
		if dq := prv.Precomputed.Dq; dq != nil {
			raw.DQ = dq.Bytes()
		}
		if qi := prv.Precomputed.Qinv; qi != nil {
			raw.QI = qi.Bytes()
		}
	}
	return nil
}

// decodeECDSA creates a decoder for the specified elliptic curve.
func decodeECDSA(
	crv elliptic.Curve,
) decoder[*ecdsa.PublicKey, *ecdsa.PrivateKey] {
	return func(raw *raw) (*ecdsa.PublicKey, *ecdsa.PrivateKey, error) {
		if raw.Kty != "EC" {
			return nil, nil, fmt.Errorf("incompatible key type %q", raw.Kty)
		}
		if raw.Crv != crv.Params().Name {
			return nil, nil, fmt.Errorf("incompatible curve %q", raw.Crv)
		}
		if len(raw.X) == 0 {
			return nil, nil, errors.New("missing x coordinate")
		}
		if len(raw.Y) == 0 {
			return nil, nil, errors.New("missing y coordinate")
		}
		x := new(big.Int).SetBytes(raw.X)
		y := new(big.Int).SetBytes(raw.Y)

		if !crv.IsOnCurve(x, y) {
			return nil, nil, errors.New("public key is not on curve")
		}

		pub := &ecdsa.PublicKey{Curve: crv, X: x, Y: y}
		if len(raw.D) == 0 {
			return pub, nil, nil
		}

		d := new(big.Int).SetBytes(raw.D)

		derivedX, derivedY := crv.ScalarBaseMult(d.Bytes())
		if derivedX.Cmp(x) != 0 || derivedY.Cmp(y) != 0 {
			return nil, nil, errors.New("public key does not match private key")
		}

		prv := &ecdsa.PrivateKey{
			PublicKey: *pub,
			D:         d,
		}

		return pub, prv, nil
	}
}

// encodeECDSA creates an encoder for the specified elliptic curve.
func encodeECDSA(
	crv elliptic.Curve,
) encoder[*ecdsa.PublicKey, *ecdsa.PrivateKey] {
	params := crv.Params()
	name, size := params.Name, (params.BitSize+7)/8
	pad := func(data []byte) []byte {
		if len(data) >= size {
			return data
		}
		padded := make([]byte, size)
		copy(padded[size-len(data):], data)
		return padded
	}
	return func(pub *ecdsa.PublicKey, prv *ecdsa.PrivateKey, raw *raw) error {
		if got := pub.Curve.Params().Name; got != name {
			return fmt.Errorf("incompatible curve %q", got)
		}
		raw.Kty = "EC"
		raw.Crv = name
		raw.X = pad(pub.X.Bytes())
		raw.Y = pad(pub.Y.Bytes())

		if prv != nil {
			raw.D = pad(prv.D.Bytes())
		}
		return nil
	}
}

// decodeEdDSA parses the material for an EdDSA key.
func decodeEdDSA(raw *raw) ([]byte, []byte, error) {
	if raw.Kty != "OKP" {
		return nil, nil, fmt.Errorf("incompatible key type %q", raw.Kty)
	}
	var size, seed int
	switch raw.Crv {
	case "Ed448":
		size = ed448.PublicKeySize
		seed = ed448.SeedSize
	case "Ed25519":
		size = ed25519.PublicKeySize
		seed = ed25519.SeedSize
	default:
		return nil, nil, fmt.Errorf("unsupported curve %q", raw.Crv)
	}
	if m := len(raw.X); m != size {
		return nil, nil, fmt.Errorf(
			"illegal key size for %s curve: got %d, want %d", raw.Crv, m, size,
		)
	}
	pub := raw.X
	if len(raw.D) == 0 {
		return pub, nil, nil
	}

	if len(raw.D) != seed {
		return nil, nil, fmt.Errorf(
			"illegal private key seed size for %s curve: got %d, want %d",
			raw.Crv, len(raw.D), seed,
		)
	}

	prv := make([]byte, seed+size)
	copy(prv[:seed], raw.D)
	copy(prv[seed:], pub)

	var derived crypto.PublicKey
	if raw.Crv == "Ed25519" {
		derived = ed25519.PrivateKey(prv).Public()
	} else {
		derived = ed448.PrivateKey(prv).Public()
	}

	if !slices.Equal(pub, derived.(ed25519.PublicKey)) {
		return nil, nil, errors.New("public key does not match private key seed")
	}

	return pub, prv, nil
}

func encodeEdDSA(pub []byte, prv []byte, raw *raw) error {
	raw.Kty = "OKP"

	var name string
	var seed int
	var size int
	switch len(pub) {
	case ed448.PublicKeySize:
		name = "Ed448"
		seed = ed448.SeedSize
		size = ed448.PrivateKeySize
	case ed25519.PublicKeySize:
		name = "Ed25519"
		seed = ed25519.SeedSize
		size = ed25519.PrivateKeySize
	default:
		return fmt.Errorf("unsupported public key size: %d", len(pub))
	}

	raw.Crv = name
	raw.X = pub

	if prv != nil {
		if len(prv) != size {
			return fmt.Errorf(
				"mismatched private key size for curve %s: got %d, want %d",
				name, len(prv), size,
			)
		}
		raw.D = prv[:seed]
	}

	return nil
}
