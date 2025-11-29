// Package jwk provides functionality to parse, manage, and marshal JSON Web
// Keys (JWK) and JSON Web Key Sets (JWKS), as defined in RFC 7517.
//
// # Verification
//
// The package is primarily designed to consume public keys from a remote JWKS
// endpoint for the purpose of verifying JWT signatures.
//
// # Signing
//
// While JWKS parsing focuses on public keys, this package also supports the
// creation of signing keys via the KeyBuilder. These keys wrap a crypto.Signer
// (e.g., hardware modules, KMS, or standard library keys) to support token
// issuance operations.
//
// # Encoding
//
// The package supports serializing keys back to JSON. This is useful for
// services that need to expose their own public keys via a JWKS endpoint or
// for persisting key sets. The marshaling logic is strict: it only outputs
// public key material and adheres to RFC 7518 fixed-width requirements for
// elliptic curve coordinates.
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
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"iter"
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

// Key represents a public JSON Web Key (JWK) used for signature verification.
type Key interface {
	Hint

	// Verify checks a signature against a message using the key's material
	// and its associated algorithm. It returns true if the signature is valid.
	// It returns false if the signature is invalid.
	Verify(msg, sig []byte) bool

	// Material returns the raw cryptographic public key for encoding purposes.
	// The private key is never exposed.
	Material() any
}

// newKey creates a new Key programmatically from its constituent parts. The
// type parameter T must match the public key type expected by the provided
// algorithm (e.g., *rsa.PublicKey for jwa.RS256).
func newKey[T crypto.PublicKey](
	alg jwa.Algorithm[T],
	kid string,
	x5t string,
	mat T,
) Key {
	return &key[T]{alg: alg, kid: kid, x5t: x5t, mat: mat}
}

// key is a concrete implementation of the Key interface, generic over the
// public key type.
type key[T crypto.PublicKey] struct {
	alg jwa.Algorithm[T]
	kid string
	x5t string
	mat T // The actual cryptographic public key material.
}

func (k *key[T]) Algorithm() string  { return k.alg.String() }
func (k *key[T]) KeyID() string      { return k.kid }
func (k *key[T]) Thumbprint() string { return k.x5t }
func (k *key[T]) Material() any      { return k.mat }

func (k *key[T]) Verify(msg, sig []byte) bool {
	return k.alg.Verify(k.mat, msg, sig)
}

// KeyPair represents a JSON Web Key that is capable of both verification and
// signing. It embeds the public Key interface and wraps a crypto.Signer for
// the private key operations.
type KeyPair interface {
	Key

	// Sign generates a signature for the given message.
	Sign(msg []byte) ([]byte, error)
}

// keyPair is the concrete implementation of KeyPair.
type keyPair[T crypto.PublicKey] struct {
	// We embed the struct value (not the pointer) so that the inner fields (alg,
	// kid, etc.) are allocated together.
	key[T]
	signer crypto.Signer
}

func (s *keyPair[T]) Sign(msg []byte) ([]byte, error) {
	return s.alg.Sign(s.signer, msg)
}

// KeyBuilder assists in the programmatic construction of Key and KeyPair
// instances. It ensures that the resulting keys possess the required metadata
// and that the cryptographic material matches the intended algorithm.
type KeyBuilder[T crypto.PublicKey] struct {
	alg jwa.Algorithm[T]
	kid string
	x5t string
}

// NewKeyBuilder starts the construction of a key for the specified algorithm.
// The generic type T determines the expected public key material (e.g.,
// *rsa.PublicKey).
func NewKeyBuilder[T crypto.PublicKey](alg jwa.Algorithm[T]) *KeyBuilder[T] {
	return &KeyBuilder[T]{alg: alg}
}

// Algorithm returns the JWA associated with this builder.
func (b *KeyBuilder[T]) Algorithm() jwa.Algorithm[T] { return b.alg }

// KeyID returns the currently configured key identifier, or an empty string.
func (b *KeyBuilder[T]) KeyID() string { return b.kid }

// Thumbprint returns the currently configured certificate thumbprint, or an
// empty string.
func (b *KeyBuilder[T]) Thumbprint() string { return b.x5t }

// WithKeyID sets the "kid" (Key ID) parameter.
func (b *KeyBuilder[T]) WithKeyID(kid string) *KeyBuilder[T] {
	b.kid = kid
	return b
}

// WithThumbprint sets the "x5t#S256" (SHA-256 Certificate Thumbprint)
// parameter.
func (b *KeyBuilder[T]) WithThumbprint(x5t string) *KeyBuilder[T] {
	b.x5t = x5t
	return b
}

// Build creates a verification-only Key using the provided public key material.
// It panics if neither a Key ID nor a Thumbprint has been configured.
func (b *KeyBuilder[T]) Build(mat T) Key {
	return b.build(mat)
}

// BuildPair creates a signing-capable KeyPair using the provided signer.
//
// It panics if:
//  1. The signer's public key cannot be cast to type T.
//  2. Neither a Key ID nor a Thumbprint has been configured.
func (b *KeyBuilder[T]) BuildPair(signer crypto.Signer) KeyPair {
	mat, ok := signer.Public().(T)
	if !ok {
		panic("signer public key type does not match key builder type")
	}
	return &keyPair[T]{
		key:    *b.build(mat),
		signer: signer,
	}
}

func (b *KeyBuilder[T]) build(mat T) *key[T] {
	if b.kid == "" && b.x5t == "" {
		panic("either key id or thumbprint must be set")
	}
	return &key[T]{
		alg: b.alg,
		kid: b.kid,
		x5t: b.x5t,
		mat: mat,
	}
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
		return nil, errors.New("undefined key type")
	}
	if raw.Alg == "" {
		return nil, errors.New("algorithm not specified")
	}
	load := loaders[raw.Alg]
	if load == nil {
		return nil, fmt.Errorf("unknown algorithm %q", raw.Alg)
	}
	key, err := load(&raw)
	if err != nil {
		return nil, fmt.Errorf("load %s key material: %w", raw.Kty, err)
	}
	return key, nil
}

// Set stores an immutable collection of Keys, typically parsed from a JWKS.
// It provides efficient lookups of keys for signature verification.
type Set interface {
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

// emptySet is pretty self-explanatory.
type emptySet struct{}

func (e emptySet) Keys() iter.Seq[Key] { return func(func(Key) bool) {} }
func (e emptySet) Len() int            { return 0 }
func (e emptySet) Find(Hint) Key       { return nil }

// empty is a singleton instance of an empty Set.
var empty Set = emptySet{}

// singletonSet is an adapter that wraps a single Key as a Set.
type singletonSet struct{ key Key }

func (s *singletonSet) Keys() iter.Seq[Key] {
	return func(f func(Key) bool) { f(s.key) }
}

func (s *singletonSet) Len() int { return 1 }

func (s *singletonSet) Find(hint Hint) Key {
	if s.key.Algorithm() == hint.Algorithm() &&
		(s.key.KeyID() == hint.KeyID() || s.key.Thumbprint() == hint.Thumbprint()) {
		return s.key
	}
	return nil
}

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
		// Defer unmarshaling of individual keys to safely skip ineligible ones.
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
		idx := -1
		kid := k.KeyID()
		if kid != "" {
			if _, ok := s.kid[kid]; ok {
				errs = append(errs, fmt.Errorf(
					"key at index %d: duplicate key id %q", i, kid,
				))
				continue
			}
			idx = len(s.keys)
			s.kid[kid] = idx
			s.keys = append(s.keys, k)
		}
		x5t := k.Thumbprint()
		if x5t != "" {
			if _, ok := s.x5t[x5t]; ok {
				errs = append(errs, fmt.Errorf(
					"key at index %d: duplicate thumbprint %q", i, x5t,
				))
				continue
			}
			idx = len(s.keys)
			s.x5t[x5t] = idx
			s.keys = append(s.keys, k)
		}
		if idx == -1 {
			errs = append(errs, fmt.Errorf(
				"key at index %d: missing both key id and thumbprint", i,
			))
			continue
		}
		s.keys[i] = k
	}
	return s, errors.Join(errs...)
}

// Write marshals a single Key into its JSON Web Key representation.
//
// It populates the standard JWK fields ("kty", "alg", "use", "kid", "x5t#S256")
// and the algorithm-specific public key parameters (e.g., "n" and "e" for RSA).
// The output is strictly compliant with RFC 7517 and RFC 7518, ensuring that
// elliptic curve coordinates are padded to the correct fixed width.
func Write(k Key) ([]byte, error) {
	r, err := toRaw(k)
	if err != nil {
		return nil, err
	}
	return json.Marshal(r)
}

// WriteSet marshals a Set into a JSON Web Key Set (JWKS) document.
//
// The resulting JSON corresponds to the standard JWKS structure:
//
//	{
//	  "keys": [ ... ]
//	}
//
// This function efficiently iterates over the keys in the set, converting them
// to their raw JSON representation before marshaling the entire collection.
func WriteSet(s Set) ([]byte, error) {
	// We marshal into a slice of raw structs directly.
	// This is more efficient than calling Write() loop, which would
	// result in double-marshaling.
	keys := make([]raw, 0, s.Len())

	for k := range s.Keys() {
		r, err := toRaw(k)
		if err != nil {
			return nil, fmt.Errorf("encode key %q: %w", k.KeyID(), err)
		}
		keys = append(keys, *r)
	}

	return json.Marshal(struct {
		Keys []raw `json:"keys"`
	}{
		Keys: keys,
	})
}

// toRaw converts a Key object into the raw DTO.
func toRaw(k Key) (*raw, error) {
	enc, ok := encoders[k.Algorithm()]
	if !ok {
		return nil, fmt.Errorf("unsupported algorithm %q", k.Algorithm())
	}

	// Populate standard metadata.
	r := &raw{
		Alg: k.Algorithm(),
		Kid: k.KeyID(),
		X5t: k.Thumbprint(),
		Use: "sig",
	}

	// Populate algorithm-specific fields.
	if err := enc(k.Material(), r); err != nil {
		return nil, err
	}

	return r, nil
}

// Singleton creates a Set that contains only the provided Key.
func Singleton(key Key) Set {
	return &singletonSet{key: key}
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

func (s *cacheSet) Keys() iter.Seq[Key] { return s.get().Keys() }
func (s *cacheSet) Len() int            { return s.get().Len() }
func (s *cacheSet) Find(hint Hint) Key  { return s.get().Find(hint) }

func (s *cacheSet) Run(ctx context.Context) time.Duration {
	return s.ctrl.Run(ctx)
}

// Ensure cacheSet implements CacheSet.
var _ CacheSet = (*cacheSet)(nil)

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

// raw holds the JWK parameters including the key material.
type raw struct {
	Kty string   `json:"kty"`
	Alg string   `json:"alg"`
	Use string   `json:"use,omitempty"`
	Ops []string `json:"key_ops,omitempty"`
	Kid string   `json:"kid,omitempty"`
	X5t string   `json:"x5t#S256,omitempty"`
	N   string   `json:"n,omitempty"`
	E   string   `json:"e,omitempty"`
	Crv string   `json:"crv,omitempty"`
	X   string   `json:"x,omitempty"`
	Y   string   `json:"y,omitempty"`
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
		return newKey(alg, r.Kid, r.X5t, mat), nil
	}
}

// decoder decodes the key material for a specific key type T.
type decoder[T crypto.PublicKey] func(*raw) (T, error)

// decodeRSA parses the material for an RSA public key.
func decodeRSA(raw *raw) (*rsa.PublicKey, error) {
	if raw.Kty != "RSA" {
		return nil, fmt.Errorf("incompatible key type %q", raw.Kty)
	}
	if len(raw.N) == 0 {
		return nil, errors.New("missing modulus")
	}
	if len(raw.E) == 0 {
		return nil, errors.New("missing public exponent")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(raw.N)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(raw.E)
	if err != nil {
		return nil, fmt.Errorf("decode public exponent: %w", err)
	}
	// Exponents > 2^31-1 are extremely rare and not recommended.
	if len(eBytes) > 4 {
		return nil, errors.New("public exponent exceeds 32 bits")
	}
	n := new(big.Int).SetBytes(nBytes)
	e := 0
	// The conversion to a big-endian unsigned integer is safe because of the
	// length check above.
	for _, b := range eBytes {
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
		if raw.Crv != crv.Params().Name {
			return nil, fmt.Errorf("incompatible curve %q", raw.Crv)
		}
		if len(raw.X) == 0 {
			return nil, errors.New("missing x coordinate")
		}
		if len(raw.Y) == 0 {
			return nil, errors.New("missing y coordinate")
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(raw.X)
		if err != nil {
			return nil, fmt.Errorf("decode x coordinate: %w", err)
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(raw.Y)
		if err != nil {
			return nil, fmt.Errorf("decode y coordinate: %w", err)
		}
		x := new(big.Int).SetBytes(xBytes)
		y := new(big.Int).SetBytes(yBytes)
		return &ecdsa.PublicKey{Curve: crv, X: x, Y: y}, nil
	}
}

// decodeEdDSA parses the material for an EdDSA public key.
func decodeEdDSA(raw *raw) ([]byte, error) {
	if raw.Kty != "OKP" {
		return nil, fmt.Errorf("incompatible key type %q", raw.Kty)
	}
	var n int
	switch raw.Crv {
	case "Ed448":
		n = ed448.PublicKeySize
	case "Ed25519":
		n = ed25519.PublicKeySize
	default:
		return nil, fmt.Errorf("unsupported curve %q", raw.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(raw.X)
	if err != nil {
		return nil, fmt.Errorf("decode x coordinate: %w", err)
	}
	if m := len(x); m != n {
		return nil, fmt.Errorf(
			"illegal key size for %s curve: got %d, want %d", raw.Crv, m, n,
		)
	}
	return x, nil
}

// encoder defines a function that populates the raw JWK parameters from the
// algorithm-specific key material.
type encoder func(mat any, r *raw) error

// encoders maps a JWA algorithm name to the function responsible for encoding
// its key material.
var encoders = map[string]encoder{
	jwa.RS256.String(): encodeRSA,
	jwa.RS384.String(): encodeRSA,
	jwa.RS512.String(): encodeRSA,
	jwa.PS256.String(): encodeRSA,
	jwa.PS384.String(): encodeRSA,
	jwa.PS512.String(): encodeRSA,
	jwa.ES256.String(): encodeECDSA,
	jwa.ES384.String(): encodeECDSA,
	jwa.ES512.String(): encodeECDSA,
	jwa.EdDSA.String(): encodeEdDSA,
}

// encodeRSA populates the RSA-specific fields ("n", "e") in the raw JWK.
func encodeRSA(mat any, r *raw) error {
	key, ok := mat.(*rsa.PublicKey)
	if !ok {
		return errors.New("invalid RSA key material")
	}
	r.Kty = "RSA"
	r.N = base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := key.E
	if e == 0 {
		return errors.New("RSA public exponent is zero")
	}
	var eBytes []byte
	if e < 0xFFFFFF {
		eBytes = make([]byte, 0, 3)
	} else {
		eBytes = make([]byte, 0, 4)
	}

	for e > 0 {
		eBytes = append([]byte{byte(e)}, eBytes...)
		e >>= 8
	}
	r.E = base64.RawURLEncoding.EncodeToString(eBytes)
	return nil
}

// encodeECDSA populates the ECDSA-specific fields ("crv", "x", "y").
// It enforces fixed-width padding for coordinates as required by RFC 7518.
func encodeECDSA(mat any, r *raw) error {
	pub, ok := mat.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("invalid ECDSA key material")
	}
	r.Kty = "EC"
	params := pub.Curve.Params()
	r.Crv = params.Name
	size := (params.BitSize + 7) / 8

	x := make([]byte, size)
	y := make([]byte, size)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)

	r.X = base64.RawURLEncoding.EncodeToString(x)
	r.Y = base64.RawURLEncoding.EncodeToString(y)
	return nil
}

// encodeEdDSA populates the EdDSA-specific fields ("crv", "x").
// It determines the curve name based on the key length.
func encodeEdDSA(mat any, r *raw) error {
	key, ok := mat.([]byte)
	if !ok {
		return errors.New("invalid EdDSA key material")
	}
	r.Kty = "OKP"

	switch len(key) {
	case ed25519.PublicKeySize:
		r.Crv = "Ed25519"
	case ed448.PublicKeySize:
		r.Crv = "Ed448"
	default:
		return fmt.Errorf("invalid EdDSA key length: %d", len(key))
	}

	r.X = base64.RawURLEncoding.EncodeToString(key)
	return nil
}
