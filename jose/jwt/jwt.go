// Package jwt provides tools for parsing and verifying JSON Web Tokens (JWTs).
//
// This package uses generics to allow users to define their own custom claims
// structures. A common pattern is to embed the provided Reserved claims
// struct and add extra fields for any other claims present in the token.
//
// # Defining Custom Claims
//
//	type Claims struct {
//	  jwt.Reserved
//	  Scope string         `json:"scp"`
//	  Extra map[string]any `json:",unknown"`
//	}
//
// # Basic Verification
//
// The top-level Verify function can be used for simple, one-off signature
// verification without claim validation:
//
//	keySet, err := jwk.ParseSet(`{"keys": [...]}`)
//	if err != nil { /* handle parsing error */ }
//	claims, err := jwt.Verify[Claims](keySet, []byte("eyJhb..."))
//
// # Advanced Validation
//
// For advanced validation of claims like issuer, audience, and token age,
// create a reusable [Verifier] with functional options:
//
//	verifier := jwt.NewVerifier[Claims](
//		keySet,
//		jwt.WithIssuer("foo", "bar"),
//		jwt.WithAudience("baz"),
//		jwt.WithLeeway(time.Minute),
//		jwt.WithMaxAge(time.Hour),
//	)
//	claims, err := verifier.Verify([]byte("eyJhb..."))
//	if err != nil { /* handle validation error */ }
//	fmt.Println("Scope:", claims.Scope)
package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/deep-rent/nexus/jose/jwk"
)

// Header represents the decoded JOSE header of a JWT.
type Header jwk.Hint

type header struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	X5t string `json:"x5t#S256"`
}

func (h *header) Type() string       { return h.Typ }
func (h *header) Algorithm() string  { return h.Alg }
func (h *header) KeyID() string      { return h.Kid }
func (h *header) Thumbprint() string { return h.X5t }

var (
	ErrKeyNotFound      = errors.New("no matching key found")
	ErrInvalidSignature = errors.New("invalid signature")
)

// Token represents a parsed, but not necessarily verified, JWT.
// The generic type T is the user-defined claims structure.
type Token[T any] interface {
	// Header returns the token's header parameters.
	Header() Header
	// Claims returns the token's payload claims.
	Claims() *T
	// Verify checks the token's signature using the provided JWK set.
	// It returns ErrKeyNotFound if no matching key is found or
	// ErrInvalidSignature if the signature is incorrect.
	Verify(set jwk.Set) error
}

// audience is a custom type to handle the JWT "aud" claim, which can be
// either a single string or an array of strings.
type token[T any] struct {
	header Header
	claims *T
	msg    []byte
	sig    []byte
}

func (t *token[T]) Header() Header { return t.header }
func (t *token[T]) Claims() *T     { return t.claims }

func (t *token[T]) Verify(set jwk.Set) error {
	key := set.Find(t.header)
	if key == nil {
		return ErrKeyNotFound
	}
	if !key.Verify(t.msg, t.sig) {
		return ErrInvalidSignature
	}
	return nil
}

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*a = audience{s}
		return nil
	}
	var m []string
	if err := json.Unmarshal(b, &m); err == nil {
		*a = audience(m)
		return nil
	}
	return errors.New("expected a string or an array of strings")
}

// Claims provides access to the standard JWT claims.
// It is used by Verifier for claim validation.
type Claims interface {
	// ID returns the "jti" (JWT ID) claim, or an empty string if absent.
	ID() string
	// Subject returns the "sub" (Subject) claim, or an empty string if absent.
	Subject() string
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

// Reserved contains the standard registered claims for a JWT. It implements
// the Claims interface and should be embedded in custom claims structs to
// enable standard claim handling.
type Reserved struct {
	Jti string    `json:"jti"`
	Sub string    `json:"sub"`
	Iss string    `json:"iss"`
	Aud audience  `json:"aud"`
	Iat time.Time `json:"iat,format:unix"`
	Exp time.Time `json:"exp,format:unix"`
	Nbf time.Time `json:"nbf,format:unix"`
}

func (r *Reserved) ID() string           { return r.Jti }
func (r *Reserved) Subject() string      { return r.Sub }
func (r *Reserved) Issuer() string       { return r.Iss }
func (r *Reserved) Audience() []string   { return r.Aud }
func (r *Reserved) IssuedAt() time.Time  { return r.Iat }
func (r *Reserved) ExpiresAt() time.Time { return r.Exp }
func (r *Reserved) NotBefore() time.Time { return r.Nbf }

// dot is the byte value for the delimiting character of JWS segments.
const dot = byte('.')

// Parse decodes a JWT from its compact serialization format into a Token
// without verifying the signature. The type parameter T specifies the target
// struct for the token's claims. If the token is malformed or the payload does
// not unmarshal into T, an error is returned.
func Parse[T any](in []byte) (Token[T], error) {
	i := bytes.IndexByte(in, dot)
	j := bytes.LastIndexByte(in, dot)
	if i <= 0 || i == j || j == len(in)-1 {
		return nil, errors.New("expected three dot-separated segments")
	}
	h, err := decode(in[:i])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}
	var header header
	if err := json.Unmarshal(h, &header); err != nil {
		return nil, fmt.Errorf("failed to unmarshal header: %w", err)
	}
	if typ := header.Typ; typ != "" && typ != "JWT" {
		return nil, fmt.Errorf("unexpected token type %q", typ)
	}
	c, err := decode(in[i+1 : j])
	if err != nil {
		return nil, fmt.Errorf("failed to decode claims: %w", err)
	}
	var claims T
	if err := json.Unmarshal(c, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}
	sig, err := decode(in[j+1:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}
	msg := in[:j]
	return &token[T]{
		header: &header,
		claims: &claims,
		msg:    msg,
		sig:    sig,
	}, nil
}

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
// set. The type parameter T specifies the target struct for the token's claims.
//
// This function only checks the cryptographic signature, not the content of the
// claims. For claim validation (e.g., issuer, audience, expiration), create and
// configure a Verifier. It is a shorthand for Parse followed by calling Verify
// on the resulting Token.
func Verify[T any](set jwk.Set, in []byte) (*T, error) {
	tok, err := Parse[T](in)
	if err != nil {
		return nil, err
	}
	if err := tok.Verify(set); err != nil {
		return nil, err
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

// Verifier is a configured, reusable JWT verifier. The type parameter T is the
// user-defined struct for the token's claims. It must implement the Claims
// interface, or else verification will always fail.
type Verifier[T any] struct {
	set       jwk.Set
	issuers   []string
	audiences []string
	leeway    time.Duration
	age       time.Duration
	now       func() time.Time
}

// Option configures a Verifier.
type Option[T any] func(*Verifier[T])

// WithIssuer adds one or more trusted issuers to the verifier. If a token's
// "iss" claim is missing or does not match one of these, it will be rejected.
// This option can be used multiple times to append additional values. By
// default, no issuer validation is performed.
func WithIssuer[T any](iss ...string) Option[T] {
	return func(v *Verifier[T]) {
		v.issuers = append(v.issuers, iss...)
	}
}

// WithAudience adds one or more trusted audiences to the verifier. If the
// token's "aud" claim is missing or does not contain at least one of these
// values, it will be rejected. This option can be used multiple times to append
// additional values. By default, no audience validation is performed.
func WithAudience[T any](aud ...string) Option[T] {
	return func(v *Verifier[T]) {
		v.audiences = append(v.audiences, aud...)
	}
}

// WithLeeway sets a grace period to allow for clock skew in temporal
// validations of the "exp", "nbf", and "iat" claims. It is subtracted from or
// added to the current time as appropriate. The default is zero, meaning no
// leeway. Negative values will be ignored.
func WithLeeway[T any](d time.Duration) Option[T] {
	return func(v *Verifier[T]) {
		if d > 0 {
			v.leeway = d
		}
	}
}

// WithMaxAge sets the maximum age for tokens based on their "iat" claim.
// Tokens without an "iat" claim will no longer be accepted. The default is
// zero, meaning no age validation. Negative values will be ignored.
func WithMaxAge[T any](d time.Duration) Option[T] {
	return func(v *Verifier[T]) {
		if d > 0 {
			v.age = d
		}
	}
}

// NewVerifier creates a new verifier bound to a specific JWK set and
// configured with the given options.
func NewVerifier[T any](set jwk.Set, opts ...Option[T]) *Verifier[T] {
	v := &Verifier[T]{
		set: set,
		now: time.Now,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Verify parses a token from its compact serialization, verifies its
// signature against the verifier's key set, and validates its claims
// according to the verifier's configuration.
func (v *Verifier[T]) Verify(in []byte) (*T, error) {
	c, err := Verify[T](v.set, in)
	if err != nil {
		return nil, err
	}
	claims, ok := any(c).(Claims)
	if !ok {
		return nil, errors.New("generic type T does not implement jwt.Claims")
	}
	now := v.now()
	if len(v.issuers) > 0 && !slices.Contains(v.issuers, claims.Issuer()) {
		return nil, ErrInvalidIssuer
	}
	if len(v.audiences) > 0 {
		found := false
		for _, aud := range v.audiences {
			if slices.Contains(claims.Audience(), aud) {
				found = true
				break
			}
		}
		if !found {
			return nil, ErrInvalidAudience
		}
	}
	if nbf := claims.NotBefore(); !nbf.IsZero() {
		if now.Add(v.leeway).Before(nbf) {
			return nil, ErrTokenNotYetActive
		}
	}
	if exp := claims.ExpiresAt(); !exp.IsZero() {
		if now.Add(-v.leeway).After(exp) {
			return nil, ErrTokenExpired
		}
	}
	if iat := claims.IssuedAt(); v.age > 0 && !iat.IsZero() {
		if iat.Add(v.age).Before(now.Add(-v.leeway)) {
			return nil, ErrTokenTooOld
		}
	}
	return c, nil
}
