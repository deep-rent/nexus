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

type Token[T any] interface {
	Header() Header
	Claims() *T
	Verify(set jwk.Set) error
}

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

type Claims interface {
	TokenID() string
	Subject() string
	Issuer() string
	Audience() []string
	IssuedAt() time.Time
	ExpiresAt() time.Time
	NotBefore() time.Time
}

type Reserved struct {
	Jti string    `json:"jti"`
	Sub string    `json:"alg"`
	Iss string    `json:"iss"`
	Aud audience  `json:"kid"`
	Iat time.Time `json:"iat,format:unix"`
	Exp time.Time `json:"exp,format:unix"`
	Nbf time.Time `json:"nbf,format:unix"`
}

func (r *Reserved) TokenID() string      { return r.Jti }
func (r *Reserved) Subject() string      { return r.Sub }
func (r *Reserved) Issuer() string       { return r.Iss }
func (r *Reserved) Audience() []string   { return r.Aud }
func (r *Reserved) IssuedAt() time.Time  { return r.Iat }
func (r *Reserved) ExpiresAt() time.Time { return r.Exp }
func (r *Reserved) NotBefore() time.Time { return r.Nbf }

const dot = byte('.')

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
	ErrInvalidIssuer     = errors.New("invalid issuer")
	ErrInvalidAudience   = errors.New("invalid audience")
	ErrTokenExpired      = errors.New("token is expired")
	ErrTokenNotYetActive = errors.New("token not yet active")
	ErrTokenTooOld       = errors.New("token is too old")
)

type Verifier[T any] interface {
	Verify(in []byte) (*T, error)
}

func NewVerifier[T any](set jwk.Set, opts ...Option[T]) Verifier[T] {
	v := &verifier[T]{
		set: set,
		now: time.Now,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

type Option[T any] func(*verifier[T])

func WithIssuer[T any](iss ...string) Option[T] {
	return func(v *verifier[T]) {
		v.issuers = append(v.issuers, iss...)
	}
}

func WithAudience[T any](aud ...string) Option[T] {
	return func(v *verifier[T]) {
		v.audiences = append(v.audiences, aud...)
	}
}

func WithLeeway[T any](d time.Duration) Option[T] {
	return func(v *verifier[T]) {
		v.leeway = d
	}
}

func WithMaxAge[T any](d time.Duration) Option[T] {
	return func(v *verifier[T]) {
		v.age = d
	}
}

type verifier[T any] struct {
	set       jwk.Set
	issuers   []string
	audiences []string
	leeway    time.Duration
	age       time.Duration
	now       func() time.Time
}

func (v *verifier[T]) Verify(in []byte) (*T, error) {
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
