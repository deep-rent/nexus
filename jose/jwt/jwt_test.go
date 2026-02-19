package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json/v2"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/jose/jwt"
)

type testClaims struct {
	jwt.Reserved
	Role string `json:"rol"`
}

func gen(t *testing.T, id string) jwk.KeyPair {
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return jwk.NewKeyBuilder(jwa.ES256).WithKeyID(id).BuildPair(raw)
}

func TestBasicSignVerify(t *testing.T) {
	k := gen(t, "k1")
	set := jwk.Singleton(k)

	input := map[string]any{
		"sub": "alice",
		"rol": "admin",
	}

	raw, err := jwt.Sign(k, input)
	require.NoError(t, err)

	out, err := jwt.Verify[*testClaims](set, raw)
	require.NoError(t, err)

	assert.Equal(t, "alice", out.Subject())
	assert.Equal(t, "admin", out.Role)
}

func TestSigner_Defaults(t *testing.T) {
	k := gen(t, "k1")
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	s := jwt.NewSigner(k).
		WithIssuer("nexus").
		WithAudience("api").
		WithLifetime(time.Hour).
		WithClock(func() time.Time { return now })

	c := &testClaims{Role: "user"}
	raw, err := s.Sign(c)
	require.NoError(t, err)

	tok, err := jwt.Parse[*testClaims](raw)
	require.NoError(t, err)

	got := tok.Claims()
	assert.Equal(t, "nexus", got.Issuer())
	assert.Equal(t, []string{"api"}, got.Audience())
	assert.Equal(t, now.Unix(), got.IssuedAt().Unix())
	assert.Equal(t, now.Add(time.Hour).Unix(), got.ExpiresAt().Unix())
	assert.Equal(t, "user", got.Role)
}

func TestSigner_Rotation(t *testing.T) {
	k1 := gen(t, "k1")
	k2 := gen(t, "k2")
	s := jwt.NewSigner(k1, k2)
	c := &testClaims{Reserved: jwt.Reserved{Sub: "test"}}

	t1, _ := s.Sign(c)
	parsed1, _ := jwt.Parse[*testClaims](t1)
	assert.Equal(t, "k1", parsed1.Header().KeyID())

	t2, _ := s.Sign(c)
	parsed2, _ := jwt.Parse[*testClaims](t2)
	assert.Equal(t, "k2", parsed2.Header().KeyID())

	t3, _ := s.Sign(c)
	parsed3, _ := jwt.Parse[*testClaims](t3)
	assert.Equal(t, "k1", parsed3.Header().KeyID())
}

func TestVerifier_Validation(t *testing.T) {
	k := gen(t, "k1")
	set := jwk.Singleton(k)
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	s := jwt.NewSigner(k).
		WithIssuer("good-iss").
		WithAudience("good-aud").
		WithLifetime(time.Hour).
		WithClock(func() time.Time { return now })

	token, _ := s.Sign(&testClaims{})

	d1 := 2 * time.Hour
	d2 := time.Hour + 30*time.Second

	tests := []struct {
		n   string
		v   *jwt.Verifier[*testClaims]
		err error
	}{
		{
			"valid",
			jwt.NewVerifier[*testClaims](set).
				WithIssuers("good-iss").
				WithAudiences("good-aud").
				WithClock(func() time.Time { return now }),
			nil,
		},
		{
			"bad issuer",
			jwt.NewVerifier[*testClaims](set).
				WithIssuers("bad-iss").
				WithClock(func() time.Time { return now }),
			jwt.ErrInvalidIssuer,
		},
		{
			"bad audience",
			jwt.NewVerifier[*testClaims](set).
				WithAudiences("bad-aud").
				WithClock(func() time.Time { return now }),
			jwt.ErrInvalidAudience,
		},
		{
			"expired",
			jwt.NewVerifier[*testClaims](set).
				WithClock(func() time.Time { return now.Add(d1) }),
			jwt.ErrTokenExpired,
		},
		{
			"leeway saves",
			jwt.NewVerifier[*testClaims](set).
				WithClock(func() time.Time { return now.Add(d2) }).
				WithLeeway(time.Minute),
			nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.n, func(t *testing.T) {
			_, err := tc.v.Verify(token)
			if tc.err == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tc.err)
			}
		})
	}
}

func TestVerifier_TimeConstraints(t *testing.T) {
	k := gen(t, "k1")
	set := jwk.Singleton(k)
	now := time.Now()

	t.Run("token not yet active", func(t *testing.T) {
		c := &testClaims{Reserved: jwt.Reserved{Nbf: now.Add(time.Hour)}}
		raw, _ := jwt.Sign(k, c)

		v := jwt.NewVerifier[*testClaims](set).
			WithClock(func() time.Time { return now })
		_, err := v.Verify(raw)
		assert.ErrorIs(t, err, jwt.ErrTokenNotYetActive)
	})

	t.Run("token too old", func(t *testing.T) {
		c := &testClaims{Reserved: jwt.Reserved{Iat: now.Add(-2 * time.Hour)}}
		raw, _ := jwt.Sign(k, c)

		v := jwt.NewVerifier[*testClaims](set).
			WithMaxAge(time.Hour).
			WithClock(func() time.Time { return now })
		_, err := v.Verify(raw)
		assert.ErrorIs(t, err, jwt.ErrTokenTooOld)
	})
}

func TestOmitEmpty(t *testing.T) {
	k := gen(t, "k1")
	raw, _ := jwt.Sign(k, &jwt.Reserved{})
	tok, _ := jwt.Parse[*jwt.Reserved](raw)
	b, _ := json.Marshal(tok.Claims())
	s := string(b)

	assert.NotContains(t, s, "jti")
	assert.NotContains(t, s, "sub")
	assert.NotContains(t, s, "iss")
	assert.NotContains(t, s, "aud")
	assert.NotContains(t, s, "iat")
	assert.NotContains(t, s, "nbf")
	assert.NotContains(t, s, "exp")
	assert.Equal(t, "{}", s)
}

func TestDynamicClaims(t *testing.T) {
	k := gen(t, "k1")
	set := jwk.Singleton(k)

	input := map[string]any{
		"sub":    "alice",
		"str":    "nexus",
		"num":    42,
		"flag":   true,
		"nested": map[string]string{"foo": "bar"},
	}

	raw, err := jwt.Sign(k, input)
	require.NoError(t, err)

	claims, err := jwt.Verify[*jwt.DynamicClaims](set, raw)
	require.NoError(t, err)

	t.Run("valid string", func(t *testing.T) {
		v, ok := jwt.Get[string](claims, "str")
		assert.True(t, ok)
		assert.Equal(t, "nexus", v)
	})

	t.Run("valid int", func(t *testing.T) {
		v, ok := jwt.Get[int](claims, "num")
		assert.True(t, ok)
		assert.Equal(t, 42, v)
	})

	t.Run("valid bool", func(t *testing.T) {
		v, ok := jwt.Get[bool](claims, "flag")
		assert.True(t, ok)
		assert.True(t, v)
	})

	t.Run("valid struct", func(t *testing.T) {
		type nested struct {
			Foo string `json:"foo"`
		}
		v, ok := jwt.Get[nested](claims, "nested")
		assert.True(t, ok)
		assert.Equal(t, "bar", v.Foo)
	})

	t.Run("missing key", func(t *testing.T) {
		_, ok := jwt.Get[string](claims, "missing")
		assert.False(t, ok)
	})

	t.Run("type mismatch", func(t *testing.T) {
		_, ok := jwt.Get[string](claims, "num")
		assert.False(t, ok)
	})

	t.Run("nil receiver", func(t *testing.T) {
		var empty *jwt.DynamicClaims
		_, ok := jwt.Get[string](empty, "str")
		assert.False(t, ok)
	})
}
