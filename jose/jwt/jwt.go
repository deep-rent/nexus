// Package jwt provides tools for parsing, verifying, and signing JSON Web
// Tokens (JWTs).
//
// This package uses generics to allow users to define their own custom claims
// structures. A common pattern is to embed the provided Reserved claims
// struct (and its pointer receivers) and add extra fields for any other
// claims present in the token.
//
// # Defining Claims
//
// To use the package, first define a struct for your claims. It must
// embed jwt.Reserved to satisfy the jwt.Claims interface.
//
//	type MyClaims struct {
//	  jwt.Reserved
//	  Scope string         `json:"scp"`
//	  Extra map[string]any `json:",unknown"`
//	}
//
// # Verifying Tokens
//
// Use a Verifier to parse and validate tokens. The fluent API allows you to
// define validation rules.
//
//	keySet, err := jwk.ParseSet(`{"keys": [...]}`)
//	if err != nil { /* handle parsing error */ }
//	verifier := jwt.NewVerifier[*MyClaims](keySet).
//	  WithIssuers("my-app").
//	  WithAudiences("my-api").
//	  WithLeeway(30*time.Second)
//
//	// Verify parses, checks signature, and validates claims
//	claims, err := verifier.Verify(tokenBytes)
//	if err != nil { /* handle validation error */ }
//
//	fmt.Println("Scope:", claims.Scope)
//
// Alternatively, you can call the standalone Verify function for a plain,
// one-off signature verification without performing claim validation.
//
// # Signing Tokens
//
// Use a Signer to create and sign new tokens. It automatically fills in
// standard claims like "iat", "nbf", "exp", "iss, "aud", and "jti".
//
//	key, err := jwk.Parse(`{...}`) // Must contain private key material
//	if err != nil { /* handle parsing error */ }
//	signer := jwt.NewSigner[*MyClaims](key).
//	  WithIssuer("my-app").
//	  WithLifetime(1*time.Hour)
//
//	// Create your claims struct (must be a pointer)
//	claims := &MyClaims{
//	  Reserved: jwt.Reserved{Sub: "user-123"},
//	  Scope:    "read:data",
//	}
//
//	// Sign will fill in iat, nbf, exp, iss, aud, and jti
//	token, err := signer.Sign(claims)
package jwt

import (
	"bytes"
	"crypto/rand"
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
type Token[T Claims] interface {
	// Header returns the token's header parameters.
	Header() Header
	// Claims returns the token's payload claims.
	Claims() T
	// Verify checks the token's signature using the provided JWK set.
	// It returns ErrKeyNotFound if no matching key is found or
	// ErrInvalidSignature if the signature is incorrect.
	Verify(set jwk.Set) error
}

// audience is a custom type to handle the JWT "aud" claim, which can be
// either a single string or an array of strings.
type token[T Claims] struct {
	header Header
	claims T
	msg    []byte
	sig    []byte
}

func (t *token[T]) Header() Header { return t.header }
func (t *token[T]) Claims() T      { return t.claims }

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
	// SetID sets the "jti" (JWT ID) claim.
	SetID(id string)
	// Subject returns the "sub" (Subject) claim, or an empty string if absent.
	Subject() string
	// SetSubject sets the "sub" (Subject) claim.
	SetSubject(sub string)
	// Issuer returns the "iss" (Issuer) claim, or an empty string if absent.
	Issuer() string
	// SetIssuer sets the "iss" (Issuer) claim.
	SetIssuer(iss string)
	// Audience returns the "aud" (Audience) claim, or nil if absent.
	Audience() []string
	// SetAudience sets the "aud" (Audience) claim.
	SetAudience(aud []string)
	// IssuedAt returns the "iat" (Issued At) claim, or the zero time if absent.
	IssuedAt() time.Time
	// SetIssuedAt sets the "iat" (Issued At) claim.
	SetIssuedAt(iat time.Time)
	// ExpiresAt returns the "exp" (Expires At) claim, or the zero time if absent.
	ExpiresAt() time.Time
	// SetExpiresAt sets the "exp" (Expires At) claim.
	SetExpiresAt(exp time.Time)
	// NotBefore returns the "nbf" (Not Before) claim, or the zero time if absent.
	NotBefore() time.Time
	// SetNotBefore sets the "nbf" (Not Before) claim.
	SetNotBefore(nbf time.Time)
}

// Reserved contains the standard registered claims for a JWT. It implements
// the Claims interface and should be embedded in custom claims structs to
// enable standard claim handling.
type Reserved struct {
	Jti string    `json:"jti"`             // JWT ID
	Sub string    `json:"sub"`             // Subject
	Iss string    `json:"iss"`             // Issuer
	Aud audience  `json:"aud"`             // Audience
	Iat time.Time `json:"iat,format:unix"` // Issued At
	Exp time.Time `json:"exp,format:unix"` // Expires At
	Nbf time.Time `json:"nbf,format:unix"` // Not Before
}

func (r *Reserved) ID() string                 { return r.Jti }
func (r *Reserved) SetID(id string)            { r.Jti = id }
func (r *Reserved) Subject() string            { return r.Sub }
func (r *Reserved) SetSubject(sub string)      { r.Sub = sub }
func (r *Reserved) Issuer() string             { return r.Iss }
func (r *Reserved) SetIssuer(iss string)       { r.Iss = iss }
func (r *Reserved) Audience() []string         { return r.Aud }
func (r *Reserved) SetAudience(aud []string)   { r.Aud = audience(aud) }
func (r *Reserved) IssuedAt() time.Time        { return r.Iat }
func (r *Reserved) SetIssuedAt(iat time.Time)  { r.Iat = iat }
func (r *Reserved) ExpiresAt() time.Time       { return r.Exp }
func (r *Reserved) SetExpiresAt(exp time.Time) { r.Exp = exp }
func (r *Reserved) NotBefore() time.Time       { return r.Nbf }
func (r *Reserved) SetNotBefore(nbf time.Time) { r.Nbf = nbf }

// dot is the byte value for the delimiting character of JWS segments.
const dot = byte('.')

// Parse decodes a JWT from its compact serialization format into a Token
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
		claims: claims,
		msg:    msg,
		sig:    sig,
	}, nil
}

func Sign[T Claims](claims T, key jwk.Key) ([]byte, error) {
	h, err := json.Marshal(header{
		Typ: "JWT",
		Alg: key.Algorithm(),
		Kid: key.KeyID(),
		X5t: key.Thumbprint(),
	})

	if err != nil {
		return nil, fmt.Errorf("failed to marshal header: %w", err)
	}

	c, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claims: %w", err)
	}

	hlen := base64.RawURLEncoding.EncodedLen(len(h))
	clen := base64.RawURLEncoding.EncodedLen(len(c))

	msg := make([]byte, hlen+1+clen)
	base64.RawURLEncoding.Encode(msg[:hlen], h)
	msg[hlen] = dot
	base64.RawURLEncoding.Encode(msg[hlen+1:], c)

	sig, err := key.Sign(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	slen := base64.RawURLEncoding.EncodedLen(len(sig))

	token := make([]byte, len(msg)+1+slen)
	copy(token, msg)
	token[len(msg)] = dot
	base64.RawURLEncoding.Encode(token[len(msg)+1:], sig)

	return token, nil
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
func Verify[T Claims](set jwk.Set, in []byte) (T, error) {
	tok, err := Parse[T](in)
	if err != nil {
		var zero T
		return zero, err
	}
	if err := tok.Verify(set); err != nil {
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

// Verifier is a configured, reusable JWT verifier. The type parameter T is the
// user-defined struct for the token's claims. It must implement the Claims
// interface, or else verification will always fail.
type Verifier[T Claims] struct {
	set      jwk.Set
	issuers  []string
	audience []string
	leeway   time.Duration
	age      time.Duration
	now      func() time.Time
}

// WithIssuer adds one or more trusted issuers to the verifier. If a token's
// "iss" claim is missing or does not match one of these, it will be rejected.
// This option can be used multiple times to append additional values. By
// default, no issuer validation is performed.
func (v *Verifier[T]) WithIssuers(iss ...string) *Verifier[T] {
	v.issuers = append(v.issuers, iss...)
	return v
}

// WithAudience adds one or more trusted audiences to the verifier. If the
// token's "aud" claim is missing or does not contain at least one of these
// values, it will be rejected. This option can be used multiple times to append
// additional values. By default, no audience validation is performed.
func (v *Verifier[T]) WithAudiences(aud ...string) *Verifier[T] {
	v.audience = append(v.audience, aud...)
	return v
}

// WithLeeway sets a grace period to allow for clock skew in temporal
// validations of the "exp", "nbf", and "iat" claims. It is subtracted from or
// added to the current time as appropriate. The default is zero, meaning no
// leeway. Negative values will be ignored.
func (v *Verifier[T]) WithLeeway(d time.Duration) *Verifier[T] {
	if d > 0 {
		v.leeway = d
	}
	return v
}

// WithMaxAge sets the maximum age for tokens based on their "iat" claim.
// Tokens without an "iat" claim will no longer be accepted. The default is
// zero, meaning no age validation. Negative values will be ignored.
func (v *Verifier[T]) WithMaxAge(d time.Duration) *Verifier[T] {
	if d > 0 {
		v.age = d
	}
	return v
}

// NewVerifier creates a new verifier bound to a specific JWK set and
// configured with the given options.
func NewVerifier[T Claims](set jwk.Set) *Verifier[T] {
	return &Verifier[T]{
		set: set,
		now: time.Now,
	}
}

// Verify parses a token from its compact serialization, verifies its
// signature against the verifier's key set, and validates its claims
// according to the verifier's configuration.
func (v *Verifier[T]) Verify(in []byte) (T, error) {
	c, err := Verify[T](v.set, in)
	if err != nil {
		var zero T
		return zero, err
	}
	now := v.now()
	if len(v.issuers) > 0 && !slices.Contains(v.issuers, c.Issuer()) {
		var zero T
		return zero, ErrInvalidIssuer
	}
	if len(v.audience) != 0 {
		found := false
		for _, aud := range v.audience {
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

type Signer struct {
	key      jwk.Key
	issuer   string
	audience []string
	lifetime time.Duration
	now      func() time.Time
}

func NewSigner(key jwk.Key) *Signer {
	if !key.IsPair() {
		panic("signing key must contain private key material")
	}
	return &Signer{
		key: key,
		now: time.Now,
	}
}

func (s *Signer) WithIssuer(iss string) *Signer {
	if iss != "" {
		s.issuer = iss
	}
	return s
}

func (s *Signer) WithAudience(aud ...string) *Signer {
	s.audience = append(s.audience, aud...)
	return s
}

func (s *Signer) WithLifetime(d time.Duration) *Signer {
	if d > 0 {
		s.lifetime = d
	}
	return s
}

func (s *Signer) WithClock(now func() time.Time) *Signer {
	if now != nil {
		s.now = now
	}
	return s
}

// Sign serializes a JWT into its compact representation, filling in standard
// claims like "iat", "nbf", "exp", "iss", "aud", and "jti" as configured. The
// claims parameter must be a pointer to a struct implementing the Claims
// interface. If any of these claims are already set in the provided struct,
// they will be overwritten. The returned JWT is signed using the signer's key.
func (s *Signer) Sign(claims Claims) ([]byte, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err // Should never happen
	}
	claims.SetID(base64.RawURLEncoding.EncodeToString(id))
	if s.issuer != "" {
		claims.SetIssuer(s.issuer)
	}
	if len(s.audience) != 0 {
		claims.SetAudience(s.audience)
	}
	claims.SetIssuedAt(s.now())
	if s.lifetime != 0 {
		iat := claims.IssuedAt()
		claims.SetNotBefore(iat)
		claims.SetExpiresAt(iat.Add(s.lifetime))
	}
	return Sign(claims, s.key)
}
