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

package google

import (
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/deep-rent/nexus/sec/iam/idp/oidc"
	"github.com/deep-rent/nexus/sec/jose/jwa"
	"github.com/deep-rent/nexus/sec/jose/jwk"
	"github.com/deep-rent/nexus/sec/jose/jwt"
)

func testConfig() Config {
	return Config{
		ClientID:     "client-1",
		ClientSecret: "s3cret",
		RedirectURI:  "https://id.example.com/oauth/callback/google",
	}
}

func TestNewValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{
			name:   "missing client id",
			mutate: func(c *Config) { c.ClientID = "" },
		},
		{
			name:   "missing secret",
			mutate: func(c *Config) { c.ClientSecret = "" },
		},
		{
			name:   "missing redirect",
			mutate: func(c *Config) { c.RedirectURI = "" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			defer func() {
				if recover() == nil {
					t.Error("should have panicked on invalid configuration")
				}
			}()

			cfg := testConfig()
			tt.mutate(&cfg)
			New(cfg)
		})
	}

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		if p := New(testConfig()); p == nil {
			t.Error("should have returned a provider")
		}
	})
}

func TestAuthURL(t *testing.T) {
	t.Parallel()

	p := New(testConfig())

	raw, err := p.AuthURL(t.Context(), "state-1")
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("failed to parse auth URL: %v", err)
	}

	if got, want := u.Host, "accounts.google.com"; got != want {
		t.Errorf("got host %q; want %q", got, want)
	}

	q := u.Query()
	if got := q.Get("client_id"); got != "client-1" {
		t.Errorf("got client_id %q; want %q", got, "client-1")
	}
	if got := q.Get("state"); got != "state-1" {
		t.Errorf("got state %q; want %q", got, "state-1")
	}
	if got := q.Get("response_type"); got != "code" {
		t.Errorf("got response_type %q; want %q", got, "code")
	}
	if got, want := q.Get("scope"), "openid email profile"; got != want {
		t.Errorf("got scope %q; want %q", got, want)
	}
}

func TestExchange(t *testing.T) {
	t.Parallel()

	key, err := jwk.Generate(jwa.ES256)
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}

	now := time.Now()

	idToken, err := jwt.Sign(t.Context(), key, &oidc.IDToken{
		Sub:           "g-123",
		Iss:           "https://accounts.google.com",
		Aud:           jwt.Audience{"client-1"},
		Iat:           now,
		Exp:           now.Add(time.Hour),
		Email:         "ada@example.com",
		EmailVerified: true,
		Name:          "Ada Lovelace",
		Picture:       "https://lh3.googleusercontent.com/ada",
	})
	if err != nil {
		t.Fatalf("failed to sign id token: %v", err)
	}

	newProvider := func(t *testing.T, srvURL string) *Provider {
		t.Helper()
		p := New(testConfig())
		p.token = srvURL
		p.verifier = jwt.NewVerifier[*oidc.IDToken](
			jwk.Singleton(key),
			jwt.WithIssuers(Issuers...),
			jwt.WithAudiences("client-1"),
		)
		return p
	}

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if got := r.FormValue(
					"grant_type",
				); got != "authorization_code" {
					t.Errorf("got grant_type %q; want authorization_code", got)
				}
				if got := r.FormValue("code"); got != "abc" {
					t.Errorf("got code %q; want %q", got, "abc")
				}
				if got := r.FormValue("client_secret"); got != "s3cret" {
					t.Errorf("got client_secret %q; want %q", got, "s3cret")
				}
				w.Header().Set("Content-Type", "application/json")
				res, _ := json.Marshal(map[string]string{
					"access_token": "at",
					"id_token":     string(idToken),
				})
				w.Write(res)
			},
		))
		defer srv.Close()

		p := newProvider(t, srv.URL)

		req := httptest.NewRequest(
			http.MethodGet,
			"/callback/google?code=abc&state=xyz",
			nil,
		)

		c, err := p.Exchange(t.Context(), req)
		if err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}
		if c.Subject != "g-123" {
			t.Errorf("got subject %q; want %q", c.Subject, "g-123")
		}
		if c.Email != "ada@example.com" || !c.EmailVerified {
			t.Errorf("unexpected email claims: %+v", c)
		}
		if c.Name != "Ada Lovelace" {
			t.Errorf("got name %q; want %q", c.Name, "Ada Lovelace")
		}
	})

	t.Run("authorization error", func(t *testing.T) {
		t.Parallel()

		p := newProvider(t, "http://invalid.invalid")

		req := httptest.NewRequest(
			http.MethodGet,
			"/callback/google?error=access_denied",
			nil,
		)
		if _, err := p.Exchange(t.Context(), req); err == nil {
			t.Fatal("should have returned an error")
		}
	})

	t.Run("missing code", func(t *testing.T) {
		t.Parallel()

		p := newProvider(t, "http://invalid.invalid")

		req := httptest.NewRequest(http.MethodGet, "/callback/google", nil)
		if _, err := p.Exchange(t.Context(), req); err == nil {
			t.Fatal("should have returned an error")
		}
	})

	t.Run("wrong audience", func(t *testing.T) {
		t.Parallel()

		foreign, err := jwt.Sign(t.Context(), key, &oidc.IDToken{
			Sub: "g-123",
			Iss: "https://accounts.google.com",
			Aud: jwt.Audience{"other-client"},
			Iat: now,
			Exp: now.Add(time.Hour),
		})
		if err != nil {
			t.Fatalf("failed to sign id token: %v", err)
		}

		srv := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				res, _ := json.Marshal(map[string]string{
					"id_token": string(foreign),
				})
				w.Write(res)
			},
		))
		defer srv.Close()

		p := newProvider(t, srv.URL)

		req := httptest.NewRequest(
			http.MethodGet,
			"/callback/google?code=abc",
			nil,
		)
		if _, err := p.Exchange(t.Context(), req); err == nil {
			t.Fatal("should have rejected the foreign audience")
		}
	})
}
