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

package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/jose/jwt"
)

type testClaims struct {
	jwt.Reserved
	Role string `json:"rol"`
}

func mockKeyPair(t *testing.T, id string) jwk.KeyPair {
	t.Helper()
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}
	return jwk.NewKeyBuilder(jwa.ES256).WithKeyID(id).BuildPair(raw)
}

func TestSignVerify(t *testing.T) {
	t.Parallel()
	k := mockKeyPair(t, "k1")
	set := jwk.Singleton(k)

	claims := map[string]any{
		"sub": "alice",
		"rol": "admin",
	}

	raw, err := jwt.Sign(k, claims)
	if err != nil {
		t.Fatalf("jwt.Sign() error = %v", err)
	}

	out, err := jwt.Verify[*testClaims](set, raw)
	if err != nil {
		t.Fatalf("jwt.Verify() error = %v", err)
	}

	if got, want := out.Subject(), "alice"; got != want {
		t.Errorf("out.Subject() = %q; want %q", got, want)
	}
	if got, want := out.Role, "admin"; got != want {
		t.Errorf("out.Role = %q; want %q", got, want)
	}
}

func TestSigner_Defaults(t *testing.T) {
	t.Parallel()
	k := mockKeyPair(t, "k1")
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	offset := 1 * time.Hour

	s := jwt.NewSigner(
		[]jwk.KeyPair{k},
		jwt.WithIssuer("nexus"),
		jwt.WithAudience("api"),
		jwt.WithLifetime(offset),
		jwt.WithSignerClock(func() time.Time { return now }),
	)

	c := &testClaims{Role: "user"}
	raw, err := s.Sign(c)
	if err != nil {
		t.Fatalf("s.Sign() error = %v", err)
	}

	tok, err := jwt.Parse[*testClaims](raw)
	if err != nil {
		t.Fatalf("jwt.Parse() error = %v", err)
	}

	got := tok.Claims()
	if got, want := got.Issuer(), "nexus"; got != want {
		t.Errorf("got.Issuer() = %q; want %q", got, want)
	}
	if got, want := got.Audience(), "api"; len(got) != 1 || got[0] != want {
		t.Errorf("got.Audience() = %v; want [%q]", got, want)
	}
	if got, want := got.IssuedAt().Unix(), now.Unix(); got != want {
		t.Errorf("got.IssuedAt() = %d; want %d", got, want)
	}
	if val, want := got.ExpiresAt().Unix(), now.Add(offset).Unix(); val != want {
		t.Errorf("got.ExpiresAt() = %d; want %d", val, want)
	}
	if val, want := got.Role, "user"; val != want {
		t.Errorf("got.Role = %q; want %q", val, want)
	}
}

func TestSigner_Rotation(t *testing.T) {
	t.Parallel()
	k1 := mockKeyPair(t, "k1")
	k2 := mockKeyPair(t, "k2")
	s := jwt.NewSigner([]jwk.KeyPair{k1, k2})
	c := &testClaims{Reserved: jwt.Reserved{Sub: "test"}}

	t1, err := s.Sign(c)
	if err != nil {
		t.Fatalf("Sign(1) error = %v", err)
	}
	parsed1, _ := jwt.Parse[*testClaims](t1)
	if got, want := parsed1.Header().KeyID(), "k1"; got != want {
		t.Errorf("KeyID(1) = %q; want %q", got, want)
	}

	t2, err := s.Sign(c)
	if err != nil {
		t.Fatalf("Sign(2) error = %v", err)
	}
	parsed2, _ := jwt.Parse[*testClaims](t2)
	if got, want := parsed2.Header().KeyID(), "k2"; got != want {
		t.Errorf("KeyID(2) = %q; want %q", got, want)
	}

	t3, err := s.Sign(c)
	if err != nil {
		t.Fatalf("Sign(3) error = %v", err)
	}
	parsed3, _ := jwt.Parse[*testClaims](t3)
	if got, want := parsed3.Header().KeyID(), "k1"; got != want {
		t.Errorf("KeyID(3) = %q; want %q", got, want)
	}
}

func TestNewSigner_Panic(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("NewSigner(nil) did not panic")
		}
	}()
	jwt.NewSigner(nil)
}

func TestVerifier_Validation(t *testing.T) {
	t.Parallel()
	k := mockKeyPair(t, "k1")
	set := jwk.Singleton(k)
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	s := jwt.NewSigner(
		[]jwk.KeyPair{k},
		jwt.WithIssuer("good-iss"),
		jwt.WithAudience("good-aud"),
		jwt.WithLifetime(time.Hour),
		jwt.WithSignerClock(func() time.Time { return now }),
	)

	token, err := s.Sign(&testClaims{})
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	d1 := 2 * time.Hour
	d2 := time.Hour + 30*time.Second

	tests := []struct {
		name    string
		v       jwt.Verifier[*testClaims]
		wantErr error
	}{
		{
			name: "valid",
			v: jwt.NewVerifier[*testClaims](
				set,
				jwt.WithIssuers("good-iss"),
				jwt.WithAudiences("good-aud"),
				jwt.WithVerifierClock(func() time.Time { return now }),
			),
			wantErr: nil,
		},
		{
			name: "bad issuer",
			v: jwt.NewVerifier[*testClaims](
				set,
				jwt.WithIssuers("bad-iss"),
				jwt.WithVerifierClock(func() time.Time { return now }),
			),
			wantErr: jwt.ErrInvalidIssuer,
		},
		{
			name: "bad audience",
			v: jwt.NewVerifier[*testClaims](
				set,
				jwt.WithAudiences("bad-aud"),
				jwt.WithVerifierClock(func() time.Time { return now }),
			),
			wantErr: jwt.ErrInvalidAudience,
		},
		{
			name: "expired",
			v: jwt.NewVerifier[*testClaims](
				set,
				jwt.WithVerifierClock(func() time.Time { return now.Add(d1) }),
			),
			wantErr: jwt.ErrTokenExpired,
		},
		{
			name: "leeway saves",
			v: jwt.NewVerifier[*testClaims](
				set,
				jwt.WithVerifierClock(func() time.Time { return now.Add(d2) }),
				jwt.WithLeeway(time.Minute),
			),
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := tt.v.Verify(token)
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("Verify() unexpected error = %v", err)
				}
			} else {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Verify() error = %v; want %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestVerifier_TimeConstraints(t *testing.T) {
	t.Parallel()
	k := mockKeyPair(t, "k1")
	set := jwk.Singleton(k)
	now := time.Now()

	t.Run("token not yet active", func(t *testing.T) {
		t.Parallel()
		c := &testClaims{Reserved: jwt.Reserved{Nbf: now.Add(time.Hour)}}
		raw, _ := jwt.Sign(k, c)

		v := jwt.NewVerifier[*testClaims](
			set,
			jwt.WithVerifierClock(func() time.Time { return now }),
		)
		if _, err := v.Verify(raw); !errors.Is(err, jwt.ErrTokenNotYetActive) {
			t.Errorf("Verify() error = %v; want %v", err, jwt.ErrTokenNotYetActive)
		}
	})

	t.Run("token too old", func(t *testing.T) {
		t.Parallel()
		c := &testClaims{Reserved: jwt.Reserved{Iat: now.Add(-2 * time.Hour)}}
		raw, _ := jwt.Sign(k, c)

		v := jwt.NewVerifier[*testClaims](
			set,
			jwt.WithMaxAge(time.Hour),
			jwt.WithVerifierClock(func() time.Time { return now }),
		)
		if _, err := v.Verify(raw); !errors.Is(err, jwt.ErrTokenTooOld) {
			t.Errorf("Verify() error = %v; want %v", err, jwt.ErrTokenTooOld)
		}
	})
}

func TestOmitEmpty(t *testing.T) {
	t.Parallel()
	k := mockKeyPair(t, "k1")
	raw, err := jwt.Sign(k, &jwt.Reserved{})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	tok, _ := jwt.Parse[*jwt.Reserved](raw)
	b, _ := json.Marshal(tok.Claims())
	got := string(b)

	keys := []string{"jti", "sub", "iss", "aud", "iat", "nbf", "exp"}
	for _, key := range keys {
		if strings.Contains(got, key) {
			t.Errorf("JSON output contains unexpected key %q: %s", key, got)
		}
	}
	if got != "{}" {
		t.Errorf("JSON output = %q; want %q", got, "{}")
	}
}

func TestDynamicClaims(t *testing.T) {
	t.Parallel()
	k := mockKeyPair(t, "k1")
	set := jwk.Singleton(k)

	input := map[string]any{
		"sub":    "alice",
		"str":    "nexus",
		"num":    42,
		"flag":   true,
		"nested": map[string]string{"foo": "bar"},
	}

	raw, err := jwt.Sign(k, input)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	claims, err := jwt.Verify[*jwt.DynamicClaims](set, raw)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	t.Run("valid string", func(t *testing.T) {
		t.Parallel()
		v, ok := jwt.Get[string](claims, "str")
		if !ok || v != "nexus" {
			t.Errorf("Get[string]() = %v, %v; want \"nexus\", true", v, ok)
		}
	})

	t.Run("valid int", func(t *testing.T) {
		t.Parallel()
		v, ok := jwt.Get[int](claims, "num")
		if !ok || v != 42 {
			t.Errorf("Get[int]() = %v, %v; want 42, true", v, ok)
		}
	})

	t.Run("valid bool", func(t *testing.T) {
		t.Parallel()
		v, ok := jwt.Get[bool](claims, "flag")
		if !ok || v != true {
			t.Errorf("Get[bool]() = %v, %v; want true, true", v, ok)
		}
	})

	t.Run("valid struct", func(t *testing.T) {
		t.Parallel()
		type nested struct {
			Foo string `json:"foo"`
		}
		v, ok := jwt.Get[nested](claims, "nested")
		if !ok || v.Foo != "bar" {
			t.Errorf("Get[struct]() = %+v, %v; want Foo: \"bar\", true", v, ok)
		}
	})

	t.Run("missing key", func(t *testing.T) {
		t.Parallel()
		if _, ok := jwt.Get[string](claims, "missing"); ok {
			t.Errorf("Get() missing key returned ok")
		}
	})

	t.Run("type mismatch", func(t *testing.T) {
		t.Parallel()
		if _, ok := jwt.Get[string](claims, "num"); ok {
			t.Errorf("Get() type mismatch returned ok")
		}
	})
}

func TestParse_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      string
		wantErr string
	}{
		{"not enough segments", "a.b", "expected three dot-separated segments"},
		{"bad header base64", "!!!.b.c", "failed to decode header"},
		{"bad header json", "dGVzdA.b.c", "failed to unmarshal header"},
		{"bad typ", "eyJ0eXAiOiJmb28ifQ.e30.c", "unexpected token type \"foo\""},
		{"bad claims base64", "eyJ0eXAiOiJKV1QifQ.!!!.c", "failed to decode claims"},
		{"bad claims json", "eyJ0eXAiOiJKV1QifQ.dGVzdA.c", "failed to unmarshal claims"},
		{"bad sig base64", "eyJ0eXAiOiJKV1QifQ.e30.!!!", "failed to decode signature"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := jwt.Parse[*testClaims]([]byte(tt.in))
			if err == nil {
				t.Fatalf("Parse() expected error; got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Parse() error = %q; want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestVerify_Errors(t *testing.T) {
	t.Parallel()
	k1 := mockKeyPair(t, "k1")
	k2 := mockKeyPair(t, "k2")

	raw, _ := jwt.Sign(k1, &testClaims{Role: "user"})

	t.Run("key not found", func(t *testing.T) {
		t.Parallel()
		set := jwk.Singleton(k2)
		if _, err := jwt.Verify[*testClaims](set, raw); !errors.Is(
			err, jwt.ErrKeyNotFound,
		) {
			t.Errorf("Verify() error = %v; want %v", err, jwt.ErrKeyNotFound)
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		t.Parallel()
		tampered := append([]byte{}, raw...)
		tampered[len(tampered)-2] = tampered[len(tampered)-2] + 1

		set := jwk.Singleton(k1)
		if _, err := jwt.Verify[*testClaims](set, tampered); !errors.Is(
			err, jwt.ErrInvalidSignature,
		) {
			t.Errorf("Verify() error = %v; want %v", err, jwt.ErrInvalidSignature)
		}
	})
}

func TestAudience_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		json    string
		want    []string
		wantErr bool
	}{
		{
			name: "single string",
			json: `{"aud":"api"}`,
			want: []string{"api"},
		},
		{
			name: "string array",
			json: `{"aud":["api","web"]}`,
			want: []string{"api", "web"},
		},
		{
			name:    "wrong type int",
			json:    `{"aud":123}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var c struct{ jwt.Reserved }
			err := json.Unmarshal([]byte(tt.json), &c)
			if tt.wantErr {
				if err == nil {
					t.Errorf("UnmarshalJSON() expected error; got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalJSON() error = %v", err)
			}
			got := c.Audience()
			if len(got) != len(tt.want) {
				t.Fatalf("Audience() length = %d; want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("Audience()[%d] = %q; want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
