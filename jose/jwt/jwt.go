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

// Package jwt provides tools for parsing, verifying, and signing JSON Web
// Tokens (JWTs).
//
// This package uses generics to allow users to define their own custom claims
// structures. A common pattern is to embed the provided [Reserved] claims
// struct and add extra fields for any other claims present in the token.
//
// # Basic Verification
//
// Start by defining custom claims:
//
//	type Claims struct {
//	  jwt.Reserved
//	  Scope string         `json:"scp"`
//	  Extra map[string]any `json:",embed"`
//	}
//
// The top-level [Verify] function can be used for simple, one-off signature
// verification without claim validation:
//
//	set, err := jwk.ParseSet(`{"keys": [...]}`)
//	if err != nil { /* handle parsing error */ }
//	claims, err := jwt.Verify[Claims](set, []byte("eyJhb..."))
//
// # Advanced Validation
//
// For advanced validation of claims like issuer, audience, and token age,
// create a reusable [Verifier] with the desired configuration using functional
// options:
//
//	verifier := jwt.NewVerifier[Claims](
//	  set,
//	  jwt.WithIssuers("foo", "bar"),
//	  jwt.WithAudiences("baz"),
//	  jwt.WithLeeway(1 * time.Minute),
//	  jwt.WithMaxAge(1 * time.Hour),
//	)
//
//	claims, err := verifier.Verify([]byte("eyJhb..."))
//	if err != nil { /* handle validation error */ }
//	fmt.Println("Scope:", claims.Scope)
//
// # Signing
//
// The top-level [Sign] function can be used to create signed tokens from any
// JSON-serializable struct or map. It requires a [jwk.KeyPair] for signature
// calculation.
//
//	claims := &MyClaims{
//	  Reserved: jwt.Reserved{
//	    Sub: "user_123",
//	    Exp: time.Now().Add(time.Hour),
//	  },
//	  Scope: "admin",
//	}
//	token, err := jwt.Sign(key, claims)
package jwt

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"uuid"

	"github.com/deep-rent/nexus/jose/jwk"
)

// Type is the media type of a JWT, as defined in RFC 7519.
const Type = "JWT"

var jsonOptions = json.JoinOptions(
	json.WithMarshalers(json.MarshalFunc(func(t time.Time) ([]byte, error) {
		if t.IsZero() {
			return []byte("null"), nil
		}
		return strconv.AppendInt(nil, t.Unix(), 10), nil
	})),
	json.WithUnmarshalers(json.UnmarshalFunc(func(b []byte, t *time.Time) error {
		if string(b) == "null" {
			*t = time.Time{}
			return nil
		}
		i, err := strconv.ParseInt(string(b), 10, 64)
		if err != nil {
			return err
		}
		*t = time.Unix(i, 0)
		return nil
	})),
)

// Header provides access to the metadata associated with a JWT, such as the
// cryptographic algorithm used to sign the token and identifiers for the
// signing key.
//
// It is an alias for [jwk.Hint], allowing it to be passed directly to a
// [jwk.Resolver]'s Find method to locate the appropriate verification key.
type Header jwk.Hint

// header is the concrete implementation of the [Header] interface, providing
// JSON tags for standard JWS header parameters.
type header struct {
	// Typ is the media type of the JWT.
	Typ string `json:"typ,omitempty"`
	// Alg is the JWA algorithm identifier.
	Alg string `json:"alg"`
	// Kid is the key identifier.
	Kid string `json:"kid,omitempty"`
}

// Type returns the "typ" parameter from the header.
func (h *header) Type() string { return h.Typ }

// Algorithm implements [jwk.Hint].
func (h *header) Algorithm() string { return h.Alg }

// KeyID implements [jwk.Hint].
func (h *header) KeyID() string { return h.Kid }

var _ Header = (*header)(nil)

var (
	// ErrKeyNotFound is returned when no matching key is found in the JWK set.
	ErrKeyNotFound = errors.New("no matching key found")
	// ErrInvalidSignature is returned when the token's signature differs from
	// the computed signature.
	ErrInvalidSignature = errors.New("invalid signature")
)

// Token represents a parsed, but not necessarily verified, JWT.
// The generic type T is the user-defined claims structure.
type Token[T Claims] interface {
	// Header returns the token's header parameters.
	Header() Header
	// Claims returns the token's payload claims.
	Claims() T
	// Verify checks the token's signature using the provided JWK resolver.
	// It returns [ErrKeyNotFound] if no matching key is found or
	// [ErrInvalidSignature] if the signature is incorrect.
	Verify(resolver jwk.Resolver) error
}

// token is the internal implementation of the [Token] interface.
type token[T Claims] struct {
	// header contains the JWS header fields.
	header Header
	// claims contains the unmarshaled payload.
	claims T
	// msg is the raw JWS Protected Header and JWS Payload.
	msg []byte
	// sig is the raw JWS Signature.
	sig []byte
}

// Header implements [Token].
func (t *token[T]) Header() Header { return t.header }

// Claims implements [Token].
func (t *token[T]) Claims() T { return t.claims }

// Verify implements [Token].
func (t *token[T]) Verify(resolver jwk.Resolver) error {
	key := resolver.Find(t.header)
	if key == nil {
		return ErrKeyNotFound
	}
	if !key.Verify(t.msg, t.sig) {
		return ErrInvalidSignature
	}
	return nil
}

var _ Token[Claims] = (*token[Claims])(nil)

// Audience represents the "aud" (Audience) claim of a JWT as defined in
// RFC 7519, Section 4.1.3.
//
// Because the "aud" claim can be either a single case-sensitive string or
// an array of such strings, this type implements custom JSON unmarshaling
// logic to ensure it is always handled as a slice of strings internally.
// Embed it in custom claims structs whenever the token source may use
// either encoding.
type Audience []string

// UnmarshalJSON handles the polymorphic nature of the "aud" claim.
func (a *Audience) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s, jsonOptions); err == nil {
		*a = Audience{s}
		return nil
	}
	var m []string
	if err := json.Unmarshal(b, &m, jsonOptions); err == nil {
		*a = Audience(m)
		return nil
	}
	return errors.New("expected a string or an array of strings")
}

// Claims provides access to the standard JWT claims.
// It is used by [Verifier] for claim validation.
type Claims interface {
	// ID returns the "jti" (JWT ID) claim, or an empty string if absent.
	ID() string
	// Subject returns the "sub" (Subject) claim, or the zero UUID if
	// absent. Subjects are user identifiers and are enforced to be UUIDs.
	Subject() uuid.UUID
	// Issuer returns the "iss" (Issuer) claim, or an empty string if absent.
	Issuer() string
	// Audience returns the "aud" (Audience) claim, or nil if absent.
	Audience() []string
	// IssuedAt returns the "iat" (Issued At) claim, or the zero time if absent.
	IssuedAt() time.Time
	// ExpiresAt returns the "exp" (Expires At) claim, or the zero time if absent.
	ExpiresAt() time.Time
	// NotBefore returns the "nbf" (Not Before) claim, or the zero time if absent.
	NotBefore() time.Time
}

// MutableClaims extends [Claims] with setters for standard JWT claims.
//
// The setter methods are not safe for concurrent use and should only be called
// during token creation.
type MutableClaims interface {
	Claims

	// SetID sets the "jti" (JWT ID) claim.
	SetID(id string)
	// SetSubject sets the "sub" (Subject) claim.
	SetSubject(sub uuid.UUID)
	// SetIssuer sets the "iss" (Issuer) claim.
	SetIssuer(iss string)
	// SetAudience sets the "aud" (Audience) claim.
	SetAudience(aud []string)
	// SetIssuedAt sets the "iat" (Issued At) claim.
	SetIssuedAt(t time.Time)
	// SetExpiresAt sets the "exp" (Expires At) claim.
	SetExpiresAt(t time.Time)
	// SetNotBefore sets the "nbf" (Not Before) claim.
	SetNotBefore(t time.Time)
}

// Reserved contains the standard registered claims for a JWT. It implements
// the [Claims] interface and should be embedded in custom claims structs to
// enable standard claim handling.
type Reserved struct {
	Jti string    `json:"jti,omitempty"` // JWT ID
	Sub uuid.UUID `json:"sub,omitzero"`  // Subject
	Iss string    `json:"iss,omitempty"` // Issuer
	Aud Audience  `json:"aud,omitempty"` // Audience
	Iat time.Time `json:"iat,omitzero"`  // Issued At
	Exp time.Time `json:"exp,omitzero"`  // Expires At
	Nbf time.Time `json:"nbf,omitzero"`  // Not Before
}

// ID implements [Claims].
func (r *Reserved) ID() string { return r.Jti }

// SetID implements [MutableClaims].
func (r *Reserved) SetID(id string) { r.Jti = id }

// Subject implements [Claims].
func (r *Reserved) Subject() uuid.UUID { return r.Sub }

// SetSubject implements [MutableClaims].
func (r *Reserved) SetSubject(sub uuid.UUID) { r.Sub = sub }

// Issuer implements [Claims].
func (r *Reserved) Issuer() string { return r.Iss }

// SetIssuer implements [MutableClaims].
func (r *Reserved) SetIssuer(iss string) { r.Iss = iss }

// Audience implements [Claims].
func (r *Reserved) Audience() []string { return r.Aud }

// SetAudience implements [MutableClaims].
func (r *Reserved) SetAudience(aud []string) { r.Aud = aud }

// IssuedAt implements [Claims].
func (r *Reserved) IssuedAt() time.Time { return r.Iat }

// SetIssuedAt implements [MutableClaims].
func (r *Reserved) SetIssuedAt(t time.Time) { r.Iat = t }

// ExpiresAt implements [Claims].
func (r *Reserved) ExpiresAt() time.Time { return r.Exp }

// SetExpiresAt implements [MutableClaims].
func (r *Reserved) SetExpiresAt(t time.Time) { r.Exp = t }

// NotBefore implements [Claims].
func (r *Reserved) NotBefore() time.Time { return r.Nbf }

// SetNotBefore implements [MutableClaims].
func (r *Reserved) SetNotBefore(t time.Time) { r.Nbf = t }

var _ MutableClaims = (*Reserved)(nil)

// DynamicClaims represents a standard JWT payload extended with arbitrary
// custom claims. It embeds the standard [Reserved] claims and captures any
// unmapped JSON properties into the Other map.
//
// By applying [jsontext.Value] and the `json:",embed"` tag from the
// encoding/json/v2 package, custom claims are retained as raw JSON bytes.
// This defers parsing until the exact target type is known, avoiding the
// common pitfalls of default map[string]any unmarshaling (such as all
// numbers defaulting to float64).
type DynamicClaims struct {
	// Reserved contains the standard registered JWT claims.
	Reserved
	// Other captures all custom claims as raw JSON.
	Other map[string]jsontext.Value `json:",embed"`
}

// Get retrieves a specific custom claim by key from the [DynamicClaims]
// payload and unmarshals it into the requested type T.
//
// It safely handles nil pointers, missing keys, and parsing errors. If the
// receiver 'c' is nil, the 'Other' map is uninitialized, the key is not
// found, or the raw JSON cannot be successfully unmarshaled into type T,
// Get returns the zero value of T and false. Otherwise, it returns the
// parsed value and true.
func (c *DynamicClaims) Get[T any](key string) (T, bool) {
	if c == nil || c.Other == nil {
		var zero T
		return zero, false
	}
	val, ok := c.Other[key]
	if !ok {
		var zero T
		return zero, false
	}
	var out T
	if err := json.Unmarshal(val, &out, jsonOptions); err != nil {
		var zero T
		return zero, false
	}
	return out, true
}

// dot is the byte value for the delimiting character of JWS segments.
const dot = byte('.')

// Parse decodes a JWT from its compact serialization format into a [Token]
// without verifying the signature. The type parameter T specifies the target
// struct for the token's claims. If the token is malformed or the payload does
// not unmarshal into T (using encoding/json/v2), an error is returned.
func Parse[T Claims](in []byte) (Token[T], error) {
	i := bytes.IndexByte(in, dot)
	j := bytes.LastIndexByte(in, dot)
	if i <= 0 || i == j || j == len(in)-1 {
		return nil, errors.New("expected three dot-separated segments")
	}
	h, err := decode(in[:i])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}
	header := new(header)
	if err := json.Unmarshal(h, header, jsonOptions); err != nil {
		return nil, fmt.Errorf("failed to unmarshal header: %w", err)
	}
	if typ := header.Typ; typ != "" && !isJWT(typ) {
		return nil, fmt.Errorf("unexpected token type %q", typ)
	}
	c, err := decode(in[i+1 : j])
	if err != nil {
		return nil, fmt.Errorf("failed to decode claims: %w", err)
	}
	var claims T
	if err := json.Unmarshal(c, &claims, jsonOptions); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}
	sig, err := decode(in[j+1:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}
	msg := in[:j]
	return &token[T]{
		header: header,
		claims: claims,
		msg:    msg,
		sig:    sig,
	}, nil
}

// isJWT checks if the token type is a JWT.
// It handles special case such as "application/jwt" and "at+jwt".
func isJWT(typ string) bool {
	typ = strings.TrimPrefix(strings.ToLower(typ), "application/")
	return typ == "jwt" || strings.HasSuffix(typ, "+jwt")
}

// decode is a helper for Base64URL decoding without padding.
func decode(src []byte) ([]byte, error) {
	n := base64.RawURLEncoding.DecodedLen(len(src))
	d := make([]byte, n)
	k, err := base64.RawURLEncoding.Decode(d, src)
	if err != nil {
		return nil, err
	}
	return d[:k], nil
}

// Verify first parses a JWT and then verifies its signature against a given key
// resolver. The type parameter T specifies the target struct for the token's
// claims.
//
// This function only checks the cryptographic signature, not the content of the
// claims. For claim validation (e.g., issuer, audience, expiration), create and
// configure a [Verifier]. It is a shorthand for [Parse] followed by calling
// [Token.Verify] on the resulting [Token].
func Verify[T Claims](resolver jwk.Resolver, in []byte) (T, error) {
	tok, err := Parse[T](in)
	if err != nil {
		var zero T
		return zero, err
	}
	if err := tok.Verify(resolver); err != nil {
		var zero T
		return zero, err
	}
	return tok.Claims(), nil
}

var (
	// ErrInvalidIssuer signals that the "iss" claim did not match any of the
	// expected issuers.
	ErrInvalidIssuer = errors.New("invalid issuer")
	// ErrInvalidAudience signals that the "aud" claim did not match any of the
	// expected audiences.
	ErrInvalidAudience = errors.New("invalid audience")
	// ErrTokenExpired signals that the "exp" claim is in the past.
	ErrTokenExpired = errors.New("token is expired")
	// ErrTokenNotYetActive signals that the "nbf" claim is in the future.
	ErrTokenNotYetActive = errors.New("token not yet active")
	// ErrTokenTooOld signals that the "iat" claim is further in the past than
	// the configured maximum age.
	ErrTokenTooOld = errors.New("token is too old")
)

// Verifier defines the interface for a configured, reusable JWT verifier. The
// type parameter T is the user-defined struct for the token's claims. It must
// implement the [Claims] interface, or else verification will always fail.
type Verifier[T Claims] interface {
	// Verify parses a token from its compact serialization, verifies its
	// signature against the verifier's key set, and validates its claims
	// according to the verifier's configuration.
	Verify(in []byte) (T, error)
}

// VerifierOption defines a functional option for configuring a [Verifier].
type VerifierOption func(*verifierConfig)

// verifierConfig holds the configuration options for a [Verifier].
type verifierConfig struct {
	issuers   []string         // Set of trusted issuers
	audiences []string         // Set of trusted audiences
	leeway    time.Duration    // Clock skew tolerance
	age       time.Duration    // Maximum allowed token age
	now       func() time.Time // Time source for temporal validation
}

// WithIssuers adds one or more trusted issuers to the verifier. If a token's
// "iss" claim is missing or does not match one of these, it will be rejected.
// This option can be used multiple times to append additional values. By
// default, no issuer validation is performed.
func WithIssuers(iss ...string) VerifierOption {
	return func(c *verifierConfig) {
		c.issuers = append(c.issuers, iss...)
	}
}

// WithAudiences adds one or more trusted audiences to the verifier. If the
// token's "aud" claim is missing or does not contain at least one of these
// values, it will be rejected. This option can be used multiple times to append
// additional values. By default, no audience validation is performed.
func WithAudiences(aud ...string) VerifierOption {
	return func(c *verifierConfig) {
		c.audiences = append(c.audiences, aud...)
	}
}

// WithLeeway sets a grace period to allow for clock skew in temporal
// validations of the "exp", "nbf", and "iat" claims. It is subtracted from or
// added to the current time as appropriate. The default is zero, meaning no
// leeway. Negative values will be ignored.
func WithLeeway(d time.Duration) VerifierOption {
	return func(c *verifierConfig) {
		if d > 0 {
			c.leeway = d
		}
	}
}

// WithMaxAge sets the maximum age for tokens based on their "iat" claim.
// Tokens without an "iat" claim will no longer be accepted. The default is
// zero, meaning no age validation. Negative values will be ignored.
func WithMaxAge(d time.Duration) VerifierOption {
	return func(c *verifierConfig) {
		if d > 0 {
			c.age = d
		}
	}
}

// WithClock sets the function used to retrieve the current time during
// validation. This is useful for deterministic testing or synchronizing with
// an external time source. The default is [time.Now].
func WithClock(now func() time.Time) VerifierOption {
	return func(c *verifierConfig) {
		if now != nil {
			c.now = now
		}
	}
}

// verifier is the default implementation of the [Verifier] interface.
type verifier[T Claims] struct {
	keys      jwk.Resolver
	issuers   []string
	audiences []string
	leeway    time.Duration
	age       time.Duration
	now       func() time.Time
}

var _ Verifier[Claims] = (*verifier[Claims])(nil)

// NewVerifier creates a new [Verifier] bound to a specific JWK resolver.
// The type parameter T is the user-defined struct for the token's claims.
func NewVerifier[T Claims](
	keys jwk.Resolver,
	opts ...VerifierOption,
) Verifier[T] {
	cfg := verifierConfig{
		now: time.Now,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return &verifier[T]{
		keys:      keys,
		issuers:   cfg.issuers,
		audiences: cfg.audiences,
		leeway:    cfg.leeway,
		age:       cfg.age,
		now:       cfg.now,
	}
}

// Verify implements the [Verifier] interface.
func (v *verifier[T]) Verify(in []byte) (T, error) {
	c, err := Verify[T](v.keys, in)
	if err != nil {
		var zero T
		return zero, err
	}
	now := v.now()
	if len(v.issuers) > 0 && !slices.Contains(v.issuers, c.Issuer()) {
		var zero T
		return zero, ErrInvalidIssuer
	}
	if len(v.audiences) > 0 {
		found := false
		for _, aud := range v.audiences {
			if slices.Contains(c.Audience(), aud) {
				found = true
				break
			}
		}
		if !found {
			var zero T
			return zero, ErrInvalidAudience
		}
	}
	if nbf := c.NotBefore(); !nbf.IsZero() {
		if now.Add(v.leeway).Before(nbf) {
			var zero T
			return zero, ErrTokenNotYetActive
		}
	}
	if exp := c.ExpiresAt(); !exp.IsZero() {
		if now.Add(-v.leeway).After(exp) {
			var zero T
			return zero, ErrTokenExpired
		}
	}
	if iat := c.IssuedAt(); v.age > 0 && !iat.IsZero() {
		if iat.Add(v.age).Before(now.Add(-v.leeway)) {
			var zero T
			return zero, ErrTokenTooOld
		}
	}
	return c, nil
}

// Sign creates a new signed JWT using the provided [jwk.KeyPair] and claims.
//
// It marshals the claims using encoding/json/v2, creates a header based on
// any type that serializes to a JSON object.
func Sign(ctx context.Context, k jwk.KeyPair, claims any) ([]byte, error) {
	// Prepare and marshal the header.
	header := &header{
		Typ: Type,
		Alg: k.Algorithm(),
		Kid: k.KeyID(),
	}

	h, err := json.Marshal(header, jsonOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal header: %w", err)
	}
	h = encode(h)

	// Marshal the claims.
	c, err := json.Marshal(claims, jsonOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claims: %w", err)
	}
	c = encode(c)

	// Construct the signing input (message).
	msg := make([]byte, 0, len(h)+1+len(c))
	msg = append(msg, h...)
	msg = append(msg, '.')
	msg = append(msg, c...)

	sig, err := k.Sign(ctx, msg)
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}
	sig = encode(sig)

	// Assemble the final token.
	token := make([]byte, 0, len(msg)+1+len(sig))
	token = append(token, msg...)
	token = append(token, dot)
	token = append(token, sig...)

	return token, nil
}

// encode is a helper for Base64URL encoding without padding.
func encode(src []byte) []byte {
	dst := make([]byte, base64.RawURLEncoding.EncodedLen(len(src)))
	base64.RawURLEncoding.Encode(dst, src)
	return dst
}
