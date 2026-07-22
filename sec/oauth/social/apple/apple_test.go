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

package apple

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/deep-rent/nexus/sec/jose/jwa"
	"github.com/deep-rent/nexus/sec/jose/jwk"
	"github.com/deep-rent/nexus/sec/jose/jwt"
	"github.com/deep-rent/nexus/sec/oauth/oidc"
)

// generatePEM returns a fresh P-256 private key encoded as PKCS#8 PEM, in
// the same shape as Apple's AuthKey_<KeyID>.p8 files, along with the key
// itself for signature verification.
func generatePEM(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}), k
}

func testConfig(t *testing.T) Config {
	t.Helper()

	pemBytes, _ := generatePEM(t)
	return Config{
		ClientID:    "com.example.web",
		TeamID:      "94Z27KF87Q",
		KeyID:       "3JD9C6QQ7A",
		PrivateKey:  pemBytes,
		RedirectURI: "https://id.example.com/oauth/callback/apple",
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
		{name: "missing team id", mutate: func(c *Config) { c.TeamID = "" }},
		{name: "missing key id", mutate: func(c *Config) { c.KeyID = "" }},
		{name: "missing key", mutate: func(c *Config) { c.PrivateKey = nil }},
		{
			name:   "missing redirect",
			mutate: func(c *Config) { c.RedirectURI = "" },
		},
		{
			name: "garbage key",
			mutate: func(c *Config) {
				c.PrivateKey = []byte("not a pem block")
			},
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

			cfg := testConfig(t)
			tt.mutate(&cfg)
			New(cfg)
		})
	}

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		if p := New(testConfig(t)); p == nil {
			t.Error("should have returned a provider")
		}
	})
}

func TestAuthURL(t *testing.T) {
	t.Parallel()

	t.Run("with scopes", func(t *testing.T) {
		t.Parallel()

		p := New(testConfig(t))

		raw, err := p.AuthURL(t.Context(), "state-1")
		if err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("failed to parse auth URL: %v", err)
		}

		if got, want := u.Host, "appleid.apple.com"; got != want {
			t.Errorf("got host %q; want %q", got, want)
		}

		q := u.Query()
		if got, want := q.Get("scope"), "name email"; got != want {
			t.Errorf("got scope %q; want %q", got, want)
		}
		// Apple mandates form_post whenever scopes are requested.
		if got, want := q.Get("response_mode"), "form_post"; got != want {
			t.Errorf("got response_mode %q; want %q", got, want)
		}
	})

	t.Run("without scopes", func(t *testing.T) {
		t.Parallel()

		cfg := testConfig(t)
		cfg.Scopes = []string{}
		p := New(cfg)

		raw, err := p.AuthURL(t.Context(), "state-1")
		if err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("failed to parse auth URL: %v", err)
		}
		if got := u.Query().Get("response_mode"); got != "" {
			t.Errorf("got response_mode %q; want it omitted", got)
		}
	})
}

func TestClientSecret(t *testing.T) {
	t.Parallel()

	cfg := testConfig(t)
	p := New(cfg)

	now := time.Unix(1_752_000_000, 0)
	p.now = func() time.Time { return now }

	secret, err := p.clientSecret(t.Context())
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	tok, err := jwt.Parse[*oidc.IDToken]([]byte(secret))
	if err != nil {
		t.Fatalf("failed to parse client secret: %v", err)
	}

	if got, want := tok.Header().KeyID(), cfg.KeyID; got != want {
		t.Errorf("got kid %q; want %q", got, want)
	}
	if got, want := tok.Header().Algorithm(), "ES256"; got != want {
		t.Errorf("got alg %q; want %q", got, want)
	}

	// The signature must verify against the provider's own key pair.
	if err := tok.Verify(jwk.Singleton(p.key)); err != nil {
		t.Fatalf("failed to verify client secret signature: %v", err)
	}

	claims := tok.Claims()
	if claims.Iss != cfg.TeamID {
		t.Errorf("got iss %q; want %q", claims.Iss, cfg.TeamID)
	}
	if claims.Sub != cfg.ClientID {
		t.Errorf("got sub %q; want %q", claims.Sub, cfg.ClientID)
	}
	if !slices.Equal(claims.Audience(), []string{Issuer}) {
		t.Errorf("got aud %v; want [%s]", claims.Audience(), Issuer)
	}
	if !claims.ExpiresAt().Equal(now.Add(SecretLifetime)) {
		t.Errorf(
			"got exp %v; want %v",
			claims.ExpiresAt(),
			now.Add(SecretLifetime),
		)
	}
}

func TestExchange(t *testing.T) {
	t.Parallel()

	appleKey, err := jwk.Generate(jwa.ES256)
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}

	now := time.Now()

	// Apple encodes email_verified as a string; use a raw claims map to
	// reproduce that quirk.
	idToken, err := jwt.Sign(t.Context(), appleKey, map[string]any{
		"sub":            "apple-123",
		"iss":            Issuer,
		"aud":            "com.example.web",
		"iat":            now,
		"exp":            now.Add(time.Hour),
		"email":          "ada@privaterelay.appleid.com",
		"email_verified": "true",
	})
	if err != nil {
		t.Fatalf("failed to sign id token: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if got := r.FormValue("grant_type"); got != "authorization_code" {
				t.Errorf("got grant_type %q; want authorization_code", got)
			}
			if got := r.FormValue("code"); got != "abc" {
				t.Errorf("got code %q; want %q", got, "abc")
			}

			// The client secret must be a well-formed, self-signed JWT.
			secret := r.FormValue("client_secret")
			tok, err := jwt.Parse[*oidc.IDToken]([]byte(secret))
			if err != nil {
				t.Errorf("failed to parse client secret: %v", err)
			} else if tok.Claims().Iss != "94Z27KF87Q" {
				t.Errorf(
					"got secret iss %q; want the team ID",
					tok.Claims().Iss,
				)
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

	p := New(testConfig(t))
	p.token = srv.URL
	p.verifier = jwt.NewVerifier[*oidc.IDToken](
		jwk.Singleton(appleKey),
		jwt.WithIssuers(Issuer),
		jwt.WithAudiences("com.example.web"),
	)

	// Apple delivers the callback as a form_post carrying the one-time
	// "user" payload on first authorization.
	form := url.Values{
		"code":  {"abc"},
		"state": {"xyz"},
		"user": {`{
			"name": {"firstName": "Ada", "lastName": "Lovelace"},
			"email": "ada@privaterelay.appleid.com"
		}`},
	}
	req := httptest.NewRequest(
		http.MethodPost,
		"/callback/apple",
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	c, err := p.Exchange(t.Context(), req)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	if c.Subject != "apple-123" {
		t.Errorf("got subject %q; want %q", c.Subject, "apple-123")
	}
	if c.Email != "ada@privaterelay.appleid.com" || !c.EmailVerified {
		t.Errorf("unexpected email claims: %+v", c)
	}
	if c.Name != "Ada Lovelace" {
		t.Errorf("got name %q; want %q", c.Name, "Ada Lovelace")
	}
}
