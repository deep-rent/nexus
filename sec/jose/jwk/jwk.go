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

package jwk

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"iter"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/deep-rent/nexus/dat/cache"
	"github.com/deep-rent/nexus/net/router"
	"github.com/deep-rent/nexus/sec/jose/jwa"
	"github.com/deep-rent/nexus/sec/sign"
	"github.com/deep-rent/nexus/sys/log"
	"github.com/deep-rent/nexus/sys/schedule"
)

// Media types as registered in RFC 7517.
const (
	MediaTypeKey = "application/jwk+json"
	MediaTypeSet = "application/jwk-set+json"
)

// Hint represents a reference to a [Key], containing the minimum information
// needed to look one up in a [Set]. It effectively abstracts the JWS header
// fields used to select a key for signature verification.
type Hint interface {
	// Algorithm returns the JWA algorithm name that the key is intended for.
	// This must match the "alg" parameter in the JWS header.
	Algorithm() string
	// KeyID returns the unique identifier for the key. This must match the
	// "kid" parameter in the JWS header.
	KeyID() string
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

// key is a concrete implementation of the [Key] interface, generic over the
// public key type.
type key[T crypto.PublicKey] struct {
	// alg is the JWA implementation for this key.
	alg jwa.Algorithm[T]
	// kid is the unique key identifier.
	kid string
	// mat is the actual cryptographic public key material.
	mat T
}

// Algorithm implements [Hint].
func (k *key[T]) Algorithm() string { return k.alg.String() }

// KeyID implements [Hint].
func (k *key[T]) KeyID() string { return k.kid }

// Material implements [Key].
func (k *key[T]) Material() any { return k.mat }

// Verify implements [Key].
func (k *key[T]) Verify(msg, sig []byte) bool {
	return k.alg.Verify(k.mat, msg, sig)
}

// KeyPair represents a JSON Web Key that is capable of both verification and
// signing. It embeds the public [Key] interface and wraps a [sign.Signer] for
// the private key operations.
type KeyPair interface {
	Key

	// Sign generates a signature for the given message.
	Sign(ctx context.Context, msg []byte) ([]byte, error)
}

// keyPair is the concrete implementation of [KeyPair].
type keyPair[T crypto.PublicKey] struct {
	// key is the underlying public key.
	key[T]
	// signer is the private key handle.
	signer sign.Signer
}

// Sign implements [KeyPair].
func (p *keyPair[T]) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	return p.alg.Sign(ctx, p.signer, msg)
}

// NewKey creates a verification-only [Key] programatically from its constituent
// parts. The type parameter T must match the public key type expected by the
// provided algorithm (e.g., [*rsa.PublicKey] for [jwa.RS256]).
func NewKey[T crypto.PublicKey](alg jwa.Algorithm[T], kid string, mat T) Key {
	return &key[T]{alg: alg, kid: kid, mat: mat}
}

// NewKeyPair creates a signing-capable [KeyPair] using the specified signer.
// It returns nil if the signer's public key cannot be cast to type T.
func NewKeyPair[T crypto.PublicKey](
	alg jwa.Algorithm[T],
	kid string,
	s sign.Signer,
) KeyPair {
	mat, ok := s.Public().(T)
	if !ok {
		return nil
	}
	return &keyPair[T]{
		alg: alg, kid: kid, mat: mat,
		signer: s,
	}
}

// NewKeyPairFor creates a signing-capable [KeyPair] by looking up the JWA
// algorithm by its standard name (e.g., "ES256"). This is useful when the
// algorithm is only known at runtime, for instance when loading keys from
// configuration.
//
// It returns an error if the algorithm is not supported, or if the signer's
// public key type does not match the algorithm.
func NewKeyPairFor(alg, kid string, s sign.Signer) (KeyPair, error) {
	pair, ok := pairers[alg]
	if !ok {
		return nil, fmt.Errorf("unsupported algorithm %q", alg)
	}
	kp := pair(kid, s)
	if kp == nil {
		return nil, fmt.Errorf(
			"public key type %T does not match algorithm %q", s.Public(), alg,
		)
	}
	return kp, nil
}

// ErrIneligibleKey indicates that a key may be syntactically valid but should
// not be used for signature verification according to its "use" or "key_ops"
// parameters.
var ErrIneligibleKey = errors.New("ineligible for signature verification")

var (
	errUndefinedKeyType     = errors.New("undefined key type")
	errUnspecifiedAlgorithm = errors.New("unspecified algorithm")
)

// Parse parses a single [Key] from the provided JSON input.
//
// It first checks if the key is eligible for signature verification. If not,
// it returns [ErrIneligibleKey]. Otherwise, it proceeds to validate the
// presence of required parameters ("kty" and "alg"), whether the algorithm is
// supported, and the integrity of the key material itself.
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
		return nil, errUndefinedKeyType
	}
	if raw.Alg == "" {
		return nil, errUnspecifiedAlgorithm
	}
	read := readers[raw.Alg]
	if read == nil {
		return nil, fmt.Errorf("unknown algorithm %q", raw.Alg)
	}
	key, err := read(&raw)
	if err != nil {
		return nil, fmt.Errorf("read %s key material: %w", raw.Kty, err)
	}
	return key, nil
}

// Resolver provides lookups of keys for signature verification.
type Resolver interface {
	// Find looks up a key using the specified hint. A key is returned only
	// if both its key id and algorithm match the hint exactly.
	// Otherwise, it returns nil.
	Find(hint Hint) Key
}

// Set stores an immutable collection of [Key] instances, typically parsed from
// a JWKS. It extends [Resolver] with the ability to iterate over all keys in
// the set and to get the number of keys.
type Set interface {
	Resolver
	// Len returns the number of keys in this set.
	Len() int

	// Keys returns an iterator over all keys in this set.
	Keys() iter.Seq[Key]
}

// newSet creates a new, empty [set] with the specified initial capacity.
func newSet(n int) *set {
	return &set{
		keys: make([]Key, 0, n),
		kidx: make(map[string]int, n),
	}
}

// set is the concrete implementation of the [Set] interface.
// It uses maps for efficient O(1) average time complexity lookups.
type set struct {
	// keys is the slice of keys in the set.
	keys []Key
	// kidx maps key id to index in keys array.
	kidx map[string]int
}

// Keys implements [Set].
func (s *set) Keys() iter.Seq[Key] { return slices.Values(s.keys) }

// Len implements [Set].
func (s *set) Len() int { return len(s.keys) }

// Find implements [Set].
func (s *set) Find(hint Hint) Key {
	if hint == nil {
		return nil
	}
	var k Key
	if i, ok := s.kidx[hint.KeyID()]; ok {
		k = s.keys[i]
	} else {
		return nil
	}
	if k.Algorithm() != hint.Algorithm() {
		return nil
	}
	return k
}

// NewSet constructs a new [Set] containing the provided keys.
//
// It is primarily used to programmatically build a JSON Web Key Set from
// individual keys, for instance when preparing to expose a JWKS endpoint.
// The keys are sorted lexicographically by their Key ID to guarantee a
// deterministic output order.
//
// If multiple keys share the same Key ID, the latter keys after sorting
// will overwrite the earlier ones in the internal lookup maps.
func NewSet(keys ...Key) Set {
	if len(keys) == 0 {
		return empty
	}
	if len(keys) == 1 {
		return Singleton(keys[0])
	}

	sorted := slices.Clone(keys)
	slices.SortFunc(sorted, compare)

	s := newSet(len(sorted))
	for _, k := range sorted {
		i := len(s.keys)
		s.keys = append(s.keys, k)
		s.kidx[k.KeyID()] = i
	}
	return s
}

// compare is a helper function used to compare two keys for sorting purposes.
func compare(a, b Key) int {
	return strings.Compare(a.KeyID(), b.KeyID())
}

// emptySet represents a [Set] containing no keys.
type emptySet struct{}

// Keys implements [Set] for [emptySet].
func (e emptySet) Keys() iter.Seq[Key] { return func(func(Key) bool) {} }

// Len implements [Set] for [emptySet].
func (e emptySet) Len() int { return 0 }

// Find implements [Set] for [emptySet].
func (e emptySet) Find(Hint) Key { return nil }

// empty is a singleton instance of an empty [Set].
var empty Set = emptySet{}

// singletonSet is an adapter that wraps a single [Key] as a [Set].
type singletonSet struct {
	// key is the single key in the set.
	key Key
}

// Keys implements [Set] for [singletonSet].
func (s *singletonSet) Keys() iter.Seq[Key] {
	return func(f func(Key) bool) { f(s.key) }
}

// Len implements [Set] for [singletonSet].
func (s *singletonSet) Len() int { return 1 }

// Find implements [Set] for [singletonSet]. It mirrors the semantics of the
// multi-key set: the hint's key id and algorithm must both match exactly.
func (s *singletonSet) Find(hint Hint) Key {
	if hint == nil {
		return nil
	}
	if s.key.KeyID() != hint.KeyID() {
		return nil
	}
	if s.key.Algorithm() != hint.Algorithm() {
		return nil
	}
	return s.key
}

// ParseSet parses a [Set] from a JWKS JSON input.
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

		kid := k.KeyID()

		if kid == "" {
			errs = append(errs, fmt.Errorf(
				"key at index %d: missing key id", i,
			))
			continue
		}
		// Check for duplicates before mutating the set.
		if _, ok := s.kidx[kid]; ok {
			errs = append(errs, fmt.Errorf(
				"key at index %d: duplicate key id %q", i, kid,
			))
			continue
		}

		// Determines the index in the keys'slice where this new key will be
		// stored. This is safe because we are appending linearly.
		idx := len(s.keys)
		// Append the key exactly once.
		s.keys = append(s.keys, k)
		// Update the lookup maps.
		s.kidx[kid] = idx
	}
	return s, errors.Join(errs...)
}

// Write marshals a single [Key] into its JSON Web Key representation.
//
// It populates the standard JWK fields ("kty", "alg", "use", "kid")
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

// WriteSet marshals a [Set] into a JSON Web Key Set (JWKS) document.
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

// toRaw converts a [Key] object into the [raw] DTO.
func toRaw(k Key) (*raw, error) {
	write, ok := writers[k.Algorithm()]
	if !ok {
		return nil, fmt.Errorf("unsupported algorithm %q", k.Algorithm())
	}

	// Populate standard metadata.
	r := &raw{
		Alg: k.Algorithm(),
		Kid: k.KeyID(),
		Use: "sig",
	}

	// Populate algorithm-specific fields.
	if err := write(k.Material(), r); err != nil {
		return nil, err
	}

	return r, nil
}

// Singleton creates a [Set] that contains only the provided [Key].
func Singleton(key Key) Set {
	return &singletonSet{key: key}
}

// CacheSet extends the [Set] interface with [schedule.Tick], creating a
// component that can be deployed to a scheduler for automatic refreshing of a
// remote JWKS view in the background. The default implementation is backed by
// a [cache.Controller].
type CacheSet interface {
	Set
	schedule.Tick

	// Ready returns a channel that is closed once the first successful fetch
	// of the remote key set has completed. Until then, the set is empty and
	// every key lookup fails; consumers can block on this channel during
	// startup to ensure verification keys are available.
	Ready() <-chan struct{}
}

// cacheSet is the concrete implementation of the [CacheSet] interface.
type cacheSet struct {
	// ctrl manages the lifecycle and fetching of the remote JWKS.
	ctrl cache.Controller[Set]
}

// get safely retrieves the current [Set] from the cache controller. If the
// cache has not been populated yet (e.g., due to an initial network failure),
// it returns a static [empty] set to ensure that delegated operations like Find
// do not panic. This makes the [Set] resilient to transient startup issues.
func (s *cacheSet) get() Set {
	if set, ok := s.ctrl.Get(); ok {
		return set
	}
	return empty
}

// Keys implements [Set].
func (s *cacheSet) Keys() iter.Seq[Key] { return s.get().Keys() }

// Len implements [Set].
func (s *cacheSet) Len() int { return s.get().Len() }

// Find implements [Set].
func (s *cacheSet) Find(hint Hint) Key { return s.get().Find(hint) }

// Run implements [schedule.Tick].
func (s *cacheSet) Run(ctx context.Context) time.Duration {
	return s.ctrl.Run(ctx)
}

// Ready implements [CacheSet].
func (s *cacheSet) Ready() <-chan struct{} { return s.ctrl.Ready() }

var _ CacheSet = (*cacheSet)(nil)

// mapper adapts the [ParseSet] function to the [cache.Mapper] interface.
var mapper cache.Mapper[Set] = func(r *cache.Response) (Set, error) {
	set, err := ParseSet(r.Body)
	if set.Len() == 0 {
		return nil, errors.New("no valid keys found")
	}
	if err != nil && r.Logger.Enabled(r.Ctx, log.LevelDebug) {
		r.Logger.Debug(
			r.Ctx,
			"Some keys could not be parsed",
			log.Error(err),
		)
	}
	// Don't complain unless there are no keys available at all.
	return set, nil
}

// NewCacheSet creates a new [CacheSet] that stays in sync with a remote JWKS
// endpoint. It must be deployed to a [schedule.] to begin the
// background fetching and refreshing process.
//
// The provided [cache.Option] can configure behaviors like refresh interval,
// request timeouts, and error handling; pass [cache.WithClient] to fetch with
// a custom [net/http.Client]. Parsing of retrieved key sets is
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
	N   string   `json:"n,omitempty"`
	E   string   `json:"e,omitempty"`
	Crv string   `json:"crv,omitempty"`
	X   string   `json:"x,omitempty"`
	Y   string   `json:"y,omitempty"`
	Pub string   `json:"pub,omitempty"`
}

// Thumbprint generates a deterministic, unique fingerprint from any standard
// public key (e.g., RSA, ECDSA, Ed25519). This fingerprint is designed to be
// used as a Key ID ("kid") for identifying keys.
//
// Note: This calculates the SHA-256 hash of the PKIX DER-encoded public key
// and returns it as a raw base64url-encoded string. It does not implement
// the JWK Thumbprint specification (RFC 7638).
func Thumbprint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	hash := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// Generate randomly generates a new signing-capable [KeyPair] for the given
// JSON Web Algorithm. The generated private key is wrapped as a [sign.Signer],
// and the Key ID ("kid") is automatically computed as the SHA-256 [Thumbprint]
// of the corresponding public key.
//
// It returns an error if the key pair generation fails, if computing the
// thumbprint fails, or if the generated key type cannot be typed to the public
// key material type T of the specified algorithm.
func Generate[T crypto.PublicKey](alg jwa.Algorithm[T]) (KeyPair, error) {
	key, err := alg.Generate()
	if err != nil {
		return nil, err
	}
	kid, err := Thumbprint(key.Public())
	if err != nil {
		return nil, err
	}
	out := NewKeyPair(alg, kid, sign.From(key))
	if out == nil {
		return nil, fmt.Errorf(
			"key type %T does not match expected algorithm key type",
			key.Public(),
		)
	}
	return out, nil
}

// Handler returns a [router.HandlerFunc] that serves the provided [Set]
// as a standard JSON Web Key Set (JWKS) document.
//
// This allows other services to dynamically fetch the public keys required
// to verify signatures. If the provided Set is a dynamically updating cache
// (such as a [CacheSet]), the handler will automatically serve the latest keys.
func Handler(s Set) router.HandlerFunc {
	return func(e *router.Exchange) error {
		data, err := WriteSet(s)
		if err != nil {
			return err
		}

		e.SetHeader("Content-Type", MediaTypeSet)
		e.Status(http.StatusOK)
		_, err = e.W.Write(data)
		return err
	}
}
