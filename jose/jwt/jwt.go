// Package jwt provides tools for parsing, verifying, and signing JSON Web
// Tokens (JWTs).
//
// This package uses generics to allow users to define their own custom claims
// structures. A common pattern is to embed the provided Reserved claims
// struct and add extra fields for any other claims present in the token.
//
// # Basic Verification
//
// Start by defining custom claims:
//
//	type Claims struct {
//	  jwt.Reserved
//	  Scope string         `json:"scp"`
//	  Extra map[string]any `json:",unknown"`
//	}
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
// create a reusable Verifier with the desired configuration:
//
//	verifier := jwt.NewVerifier[Claims](keySet).
//		WithIssuer("foo", "bar").
//		WithAudience("baz").
//		WithLeeway(1 * time.Minute).
//		WithMaxAge(1 * time.Hour)
//
//	claims, err := verifier.Verify([]byte("eyJhb..."))
//	if err != nil { /* handle validation error */ }
//	fmt.Println("Scope:", claims.Scope)
//
// # Basic Signing
//
// The top-level Sign function can be used to create signed tokens from any
// JSON-serializable struct or map. This is useful for simple tokens where
// you manually handle all claims:
//
//	// keyPair must be a jwk.KeyPair (containing a private key)
//	claims := map[string]any{"sub": "user_123", "admin": true}
//	token, err := jwt.Sign(keyPair, claims)
//
// # Advanced Signing
//
// To enforce policies like expiration or consistent issuers, create a reusable
// Signer. Your claims struct must implement MutableClaims (embedding
// jwt.Reserved handles this automatically).
//
//	signer := jwt.NewSigner(keyPair).
//	    WithIssuer("https://api.example.com").
//	    WithLifetime(1 * time.Hour)
//
//	// The signer will automatically set "iss", "iat", and "exp" on the struct.
//	claims := &MyClaims{
//	    Reserved: jwt.Reserved{Subject: "user_123"},
//	    Scope:    "admin",
//	}
//	token, err := signer.Sign(claims)
package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/deep-rent/nexus/internal/rotator"
	"github.com/deep-rent/nexus/jose/jwk"
)

// Header represents the decoded JOSE header of a JWT.
type Header jwk.Hint

type header struct {
	Typ string `json:"typ,omitempty"`
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
	X5t string `json:"x5t#S256,omitempty"`
}

func (h *header) Type() string       { return h.Typ }
func (h *header) Algorithm() string  { return h.Alg }
func (h *header) KeyID() string      { return h.Kid }
func (h *header) Thumbprint() string { return h.X5t }

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

// MutableClaims extends Claims with setters for standard JWT claims.
//
// The setter methods are not safe for concurrent use and should only be called
// during token creation.
type MutableClaims interface {
	Claims

	// SetID sets the "jti" (JWT ID) claim.
	SetID(id string)
	// SetSubject sets the "sub" (Subject) claim.
	SetSubject(sub string)
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
// the Claims interface and should be embedded in custom claims structs to
// enable standard claim handling.
type Reserved struct {
	Jti string    `json:"jti,omitempty"`            // JWT ID
	Sub string    `json:"sub,omitempty"`            // Subject
	Iss string    `json:"iss,omitempty"`            // Issuer
	Aud audience  `json:"aud,omitempty"`            // Audience
	Iat time.Time `json:"iat,omitzero,format:unix"` // Issued At
	Exp time.Time `json:"exp,omitzero,format:unix"` // Expires At
	Nbf time.Time `json:"nbf,omitzero,format:unix"` // Not Before
}

func (r *Reserved) ID() string               { return r.Jti }
func (r *Reserved) SetID(id string)          { r.Jti = id }
func (r *Reserved) Subject() string          { return r.Sub }
func (r *Reserved) SetSubject(sub string)    { r.Sub = sub }
func (r *Reserved) Issuer() string           { return r.Iss }
func (r *Reserved) SetIssuer(iss string)     { r.Iss = iss }
func (r *Reserved) Audience() []string       { return r.Aud }
func (r *Reserved) SetAudience(aud []string) { r.Aud = aud }
func (r *Reserved) IssuedAt() time.Time      { return r.Iat }
func (r *Reserved) SetIssuedAt(t time.Time)  { r.Iat = t }
func (r *Reserved) ExpiresAt() time.Time     { return r.Exp }
func (r *Reserved) SetExpiresAt(t time.Time) { r.Exp = t }
func (r *Reserved) NotBefore() time.Time     { return r.Nbf }
func (r *Reserved) SetNotBefore(t time.Time) { r.Nbf = t }

// Ensure Reserved implements the MutableClaims interface.
var _ MutableClaims = (*Reserved)(nil)

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
	header := new(header)
	if err := json.Unmarshal(h, header); err != nil {
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
		header: header,
		claims: claims,
		msg:    msg,
		sig:    sig,
	}, nil
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
	set       jwk.Set
	issuers   []string
	audiences []string
	leeway    time.Duration
	age       time.Duration
	now       func() time.Time
}

// WithIssuers adds one or more trusted issuers to the verifier. If a token's
// "iss" claim is missing or does not match one of these, it will be rejected.
// This option can be used multiple times to append additional values. By
// default, no issuer validation is performed.
//
// This method is not thread-safe and should be called only during setup.
func (v *Verifier[T]) WithIssuers(iss ...string) *Verifier[T] {
	v.issuers = append(v.issuers, iss...)
	return v
}

// WithAudiences adds one or more trusted audiences to the verifier. If the
// token's "aud" claim is missing or does not contain at least one of these
// values, it will be rejected. This option can be used multiple times to append
// additional values. By default, no audience validation is performed.
//
// This method is not thread-safe and should be called only during setup.
func (v *Verifier[T]) WithAudiences(aud ...string) *Verifier[T] {
	v.audiences = append(v.audiences, aud...)
	return v
}

// WithLeeway sets a grace period to allow for clock skew in temporal
// validations of the "exp", "nbf", and "iat" claims. It is subtracted from or
// added to the current time as appropriate. The default is zero, meaning no
// leeway. Negative values will be ignored.
//
// This method is not thread-safe and should be called only during setup.
func (v *Verifier[T]) WithLeeway(d time.Duration) *Verifier[T] {
	if d > 0 {
		v.leeway = d
	}
	return v
}

// WithMaxAge sets the maximum age for tokens based on their "iat" claim.
// Tokens without an "iat" claim will no longer be accepted. The default is
// zero, meaning no age validation. Negative values will be ignored.
//
// This method is not thread-safe and should be called only during setup.
func (v *Verifier[T]) WithMaxAge(d time.Duration) *Verifier[T] {
	if d > 0 {
		v.age = d
	}
	return v
}

// WithClock sets the function used to retrieve the current time during
// validation. This is useful for deterministic testing or synchronizing with
// an external time source. The default is time.Now.
//
// This method is not thread-safe and should be called only during setup.
func (v *Verifier[T]) WithClock(now func() time.Time) *Verifier[T] {
	if now != nil {
		v.now = now
	}
	return v
}

// NewVerifier creates a new verifier bound to a specific JWK set.
// The type parameter T is the user-defined struct for the token's claims.
// Further configuration can be applied using the With... setters.
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

// Sign creates a new signed JWT using the provided KeyPair and claims.
//
// It marshals the claims using encoding/json/v2, creates a header based on
// the key's properties, and signs the payload. The claims argument can be
// any type that serializes to a JSON object.
func Sign(k jwk.KeyPair, claims any) ([]byte, error) {
	// Prepare and marshal the header.
	header := &header{
		Typ: "JWT",
		Alg: k.Algorithm(),
		Kid: k.KeyID(),
		X5t: k.Thumbprint(),
	}

	h, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal header: %w", err)
	}
	h = encode(h)

	// Marshal the claims.
	c, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claims: %w", err)
	}
	c = encode(c)

	// Construct the signing input (message).
	msg := make([]byte, 0, len(h)+1+len(c))
	msg = append(msg, h...)
	msg = append(msg, dot)
	msg = append(msg, c...)

	// Sign the message.
	sig, err := k.Sign(msg)
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

// Signer is a configured, reusable JWT creator. It allows setting default
// claims (like Issuer and Audience) and enforcing token lifetime (Expiration).
type Signer struct {
	rot rotator.Rotator[jwk.KeyPair]
	iat bool
	iss string
	aud []string
	ttl time.Duration
	now func() time.Time
}

// NewSigner creates a new Signer that uses the provided key pairs for signing.
// At least one key pair must be provided; otherwise, it panics. Further
// configuration can be applied using the With... setters.
func NewSigner(keys ...jwk.KeyPair) *Signer {
	return &Signer{
		rot: rotator.New(keys),
		iat: true,
		now: time.Now,
	}
}

// WithIssuedAt enables or disables automatic setting of the "iat" (Issued At)
// claim for all tokens created by this signer. It is enabled by default and
// will be stamped with the current time.
//
// This method is not thread-safe and should be called only during setup.
func (s *Signer) WithIssuedAt(use bool) *Signer {
	s.iat = use
	return s
}

// WithIssuer sets the "iss" (Issuer) claim for all tokens created by this
// signer. If the user-provided claims already contain an issuer, this
// configuration will overwrite it.
//
// This method is not thread-safe and should be called only during setup.
func (s *Signer) WithIssuer(iss string) *Signer {
	s.iss = iss
	return s
}

// WithAudience sets the "aud" (Audience) claim. If the user-provided claims
// already contain an audience, this configuration will overwrite it.
//
// This method is not thread-safe and should be called only during setup.
func (s *Signer) WithAudience(aud ...string) *Signer {
	s.aud = aud
	return s
}

// WithLifetime sets the duration for which tokens are valid. It calculates the
// "exp" (Expires At) claim by adding this duration to the current time.
// If zero (default), no "exp" claim is added unless provided in the input
// claims.
//
// This method is not thread-safe and should be called only during setup.
func (s *Signer) WithLifetime(d time.Duration) *Signer {
	if d > 0 {
		s.ttl = d
	}
	return s
}

// WithClock sets the function used to retrieve the current time when
// timestamping tokens ("iat", "nbf", "exp"). This is useful for deterministic
// testing. The default is time.Now.
//
// This method is not thread-safe and should be called only during setup.
func (s *Signer) WithClock(now func() time.Time) *Signer {
	if now != nil {
		s.now = now
	}
	return s
}

// Sign applies the signer's configuration (issuer, audience, and temporal
// validity) directly to the mutable claims object, then signs it.
func (s *Signer) Sign(claims MutableClaims) ([]byte, error) {
	now := s.now()
	// Always stamp the current time as time of issuance.
	if s.iat {
		claims.SetIssuedAt(now)
	}
	// Apply configured issuer name.
	if s.iss != "" {
		claims.SetIssuer(s.iss)
	}
	// Apply configured audience.
	if len(s.aud) > 0 {
		claims.SetAudience(s.aud)
	}
	// Calculate and apply expiration if a lifetime is configured.
	if s.ttl > 0 {
		claims.SetExpiresAt(now.Add(s.ttl))
	}
	key := s.rot.Next()
	// Delegate to the low-level Sign function.
	return Sign(key, claims)
}
