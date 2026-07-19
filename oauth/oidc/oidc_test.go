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

package oidc

import (
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/jose/jwt"
)

func TestBoolishUnmarshal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      string
		want    bool
		wantErr bool
	}{
		{name: "true", in: `true`, want: true},
		{name: "false", in: `false`, want: false},
		{name: "string true", in: `"true"`, want: true},
		{name: "string false", in: `"false"`, want: false},
		{name: "invalid", in: `"maybe"`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var b Boolish
			err := json.Unmarshal([]byte(tt.in), &b)
			if tt.wantErr {
				if err == nil {
					t.Fatal("should have returned an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("should not have returned an error: %v", err)
			}
			if bool(b) != tt.want {
				t.Errorf("got %t; want %t", b, tt.want)
			}
		})
	}
}

func TestIDTokenRoundTrip(t *testing.T) {
	t.Parallel()

	key, err := jwk.Generate(jwa.ES256)
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}

	now := time.Now().Truncate(time.Second)

	src := &IDToken{
		Sub:           "ext-123",
		Iss:           "https://idp.example.com",
		Aud:           jwt.Audience{"client-1"},
		Iat:           now,
		Exp:           now.Add(time.Hour),
		Email:         "ada@example.com",
		EmailVerified: true,
		Name:          "Ada Lovelace",
		Picture:       "https://idp.example.com/ada.png",
	}

	token, err := jwt.Sign(t.Context(), key, src)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	verifier := jwt.NewVerifier[*IDToken](
		jwk.Singleton(key),
		jwt.WithIssuers("https://idp.example.com"),
		jwt.WithAudiences("client-1"),
	)

	claims, err := verifier.Verify(token)
	if err != nil {
		t.Fatalf("failed to verify token: %v", err)
	}

	if claims.Sub != src.Sub {
		t.Errorf("got sub %q; want %q", claims.Sub, src.Sub)
	}
	if !claims.ExpiresAt().Equal(src.Exp) {
		t.Errorf("got exp %v; want %v", claims.ExpiresAt(), src.Exp)
	}

	c := claims.Claimant()
	if c.Subject != "ext-123" {
		t.Errorf("got subject %q; want %q", c.Subject, "ext-123")
	}
	if c.Email != "ada@example.com" || !c.EmailVerified {
		t.Errorf("unexpected email claims: %+v", c)
	}
	if c.Name != "Ada Lovelace" {
		t.Errorf("got name %q; want %q", c.Name, "Ada Lovelace")
	}
}

func TestExchange(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("got method %q; want POST", r.Method)
				}
				if got := r.FormValue("code"); got != "abc" {
					t.Errorf("got code %q; want %q", got, "abc")
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(
					`{"access_token":"at","id_token":"idt",` +
						`"token_type":"Bearer","expires_in":3600}`,
				))
			},
		))
		defer srv.Close()

		tok, err := Exchange(t.Context(), srv.Client(), srv.URL, url.Values{
			"code": {"abc"},
		})
		if err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}
		if tok.AccessToken != "at" || tok.IDToken != "idt" {
			t.Errorf("unexpected token response: %+v", tok)
		}
		if tok.ExpiresIn != 3600 {
			t.Errorf("got expires_in %d; want 3600", tok.ExpiresIn)
		}
	})

	t.Run("provider error", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(
					`{"error":"invalid_grant",` +
						`"error_description":"code expired"}`,
				))
			},
		))
		defer srv.Close()

		_, err := Exchange(t.Context(), srv.Client(), srv.URL, url.Values{})
		if err == nil {
			t.Fatal("should have returned an error")
		}
		want := `token endpoint returned "invalid_grant": code expired`
		if err.Error() != want {
			t.Errorf("got error %q; want %q", err, want)
		}
	})

	t.Run("opaque error", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
		))
		defer srv.Close()

		_, err := Exchange(t.Context(), srv.Client(), srv.URL, url.Values{})
		if err == nil {
			t.Fatal("should have returned an error")
		}
	})
}

func TestCallback(t *testing.T) {
	t.Parallel()

	key, err := jwk.Generate(jwa.ES256)
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}

	now := time.Now()

	idToken, err := jwt.Sign(t.Context(), key, &IDToken{
		Sub: "ext-123",
		Iss: "https://idp.example.com",
		Aud: jwt.Audience{"client-1"},
		Iat: now,
		Exp: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to sign id token: %v", err)
	}

	verifier := jwt.NewVerifier[*IDToken](
		jwk.Singleton(key),
		jwt.WithIssuers("https://idp.example.com"),
		jwt.WithAudiences("client-1"),
	)

	credentials := func() url.Values {
		return url.Values{
			"client_id":     {"client-1"},
			"client_secret": {"s3cret"},
		}
	}

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				// Callback must fill in the protocol parameters while
				// preserving the provided client credentials.
				if got := r.FormValue("grant_type"); got != "authorization_code" {
					t.Errorf("got grant_type %q; want authorization_code", got)
				}
				if got := r.FormValue("code"); got != "abc" {
					t.Errorf("got code %q; want %q", got, "abc")
				}
				if got := r.FormValue("redirect_uri"); got != "https://rp.example.com/cb" {
					t.Errorf("got redirect_uri %q; want the configured URI", got)
				}
				if got := r.FormValue("client_secret"); got != "s3cret" {
					t.Errorf("got client_secret %q; want %q", got, "s3cret")
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"id_token":"` + string(idToken) + `"}`))
			},
		))
		defer srv.Close()

		req := httptest.NewRequest(http.MethodGet, "/cb?code=abc", nil)

		claims, err := Callback(
			t.Context(),
			srv.Client(),
			srv.URL,
			req,
			credentials(),
			"https://rp.example.com/cb",
			verifier,
		)
		if err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}
		if claims.Sub != "ext-123" {
			t.Errorf("got sub %q; want %q", claims.Sub, "ext-123")
		}
	})

	t.Run("authorization error", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(
			http.MethodGet,
			"/cb?error=access_denied",
			nil,
		)
		_, err := Callback(
			t.Context(),
			http.DefaultClient,
			"http://invalid.invalid",
			req,
			credentials(),
			"https://rp.example.com/cb",
			verifier,
		)
		if err == nil {
			t.Fatal("should have returned an error")
		}
	})

	t.Run("missing code", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodGet, "/cb", nil)
		_, err := Callback(
			t.Context(),
			http.DefaultClient,
			"http://invalid.invalid",
			req,
			credentials(),
			"https://rp.example.com/cb",
			verifier,
		)
		if err == nil {
			t.Fatal("should have returned an error")
		}
	})

	t.Run("missing id token", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"access_token":"at"}`))
			},
		))
		defer srv.Close()

		req := httptest.NewRequest(http.MethodGet, "/cb?code=abc", nil)
		_, err := Callback(
			t.Context(),
			srv.Client(),
			srv.URL,
			req,
			credentials(),
			"https://rp.example.com/cb",
			verifier,
		)
		if err == nil {
			t.Fatal("should have returned an error")
		}
	})

	t.Run("verification failure", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"id_token":"garbage"}`))
			},
		))
		defer srv.Close()

		req := httptest.NewRequest(http.MethodGet, "/cb?code=abc", nil)
		_, err := Callback(
			t.Context(),
			srv.Client(),
			srv.URL,
			req,
			credentials(),
			"https://rp.example.com/cb",
			verifier,
		)
		if err == nil {
			t.Fatal("should have returned an error")
		}
	})
}
