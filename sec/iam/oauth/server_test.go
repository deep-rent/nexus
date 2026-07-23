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

package oauth_test

import (
	"context"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"uuid"

	"github.com/deep-rent/nexus/net/router"
	"github.com/deep-rent/nexus/sec/iam/artifact"
	"github.com/deep-rent/nexus/sec/iam/oauth"
	"github.com/deep-rent/nexus/sec/iam/oauth/grant"
	"github.com/deep-rent/nexus/sec/jose/jwa"
	"github.com/deep-rent/nexus/sec/jose/jwk"
	"github.com/deep-rent/nexus/sec/vault"
	"github.com/deep-rent/nexus/std/rotor"
)

// m2mClient is a minimal confidential machine-to-machine client.
type m2mClient struct {
	id     uuid.UUID
	secret string
}

func (c *m2mClient) ID() uuid.UUID      { return c.id }
func (c *m2mClient) Public() bool       { return false }
func (c *m2mClient) Audience() []string { return nil }

func (c *m2mClient) VerifySecret(
	secret string,
) bool {
	return secret == c.secret
}
func (c *m2mClient) VerifyRedirectURI(string) bool { return false }
func (c *m2mClient) CanUseGrant(g oauth.GrantType) bool {
	return g == oauth.GrantTypeClientCredentials
}
func (c *m2mClient) CanUseScope(string) bool { return true }

var _ oauth.Client = (*m2mClient)(nil)

// m2mClientStore serves a single registered client.
type m2mClientStore struct {
	client *m2mClient
}

func (s *m2mClientStore) GetClient(
	_ context.Context,
	id uuid.UUID,
) (oauth.Client, error) {
	if id == s.client.id {
		return s.client, nil
	}
	return nil, nil
}

// TestServer_Standalone proves the authorization server mounts and serves
// tokens without any composing login machinery: no session resolver, no
// owner resolver, no login endpoints — just clients, stores, and a vault.
func TestServer_Standalone(t *testing.T) {
	t.Parallel()

	key, err := jwk.Generate(jwa.ES256)
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}

	client := &m2mClient{id: uuid.New(), secret: "s3cret"}

	s := oauth.NewServer(oauth.ServerConfig{
		Vault:   vault.New([]jwk.KeyPair{key}, rotor.Sequential),
		Clients: &m2mClientStore{client: client},
		Tokens: oauth.TokenStores{
			AuthCodes: artifact.NewMap(
				func(c oauth.AuthCode) oauth.Digest { return c.Code },
			),
			RefreshTokens: artifact.NewMap(
				func(r oauth.RefreshToken) oauth.Digest { return r.Token },
			),
		},
		Issuer: "https://id.example.com",
	}, oauth.WithGrant(grant.ClientCredentials()))

	r := router.New()
	s.Mount(r, "/oauth")

	do := func(req *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	t.Run("well-known", func(t *testing.T) {
		w := do(httptest.NewRequest(
			http.MethodGet,
			"/oauth"+oauth.PathWellKnown,
			nil,
		))
		if w.Code != http.StatusOK {
			t.Fatalf(
				"got status %d; want %d: %s",
				w.Code,
				http.StatusOK,
				w.Body,
			)
		}
		var meta oauth.ServerMetadata
		if err := json.Unmarshal(w.Body.Bytes(), &meta); err != nil {
			t.Fatalf("failed to decode metadata: %v", err)
		}
		if meta.Issuer != "https://id.example.com" {
			t.Errorf("got issuer %q", meta.Issuer)
		}
		if got := meta.GrantTypesSupported; len(got) != 1 ||
			got[0] != string(oauth.GrantTypeClientCredentials) {
			t.Errorf("got grant types %v; want client_credentials only", got)
		}
	})

	t.Run("jwks", func(t *testing.T) {
		w := do(httptest.NewRequest(
			http.MethodGet,
			"/oauth"+oauth.PathKeySet,
			nil,
		))
		if w.Code != http.StatusOK {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("client credentials token", func(t *testing.T) {
		form := url.Values{
			"grant_type": {string(oauth.GrantTypeClientCredentials)},
			"scope":      {"read"},
		}
		req := httptest.NewRequest(
			http.MethodPost,
			"/oauth"+oauth.PathToken,
			strings.NewReader(form.Encode()),
		)
		req.Header.Set(
			"Content-Type",
			"application/x-www-form-urlencoded",
		)
		req.SetBasicAuth(client.id.String(), "s3cret")

		w := do(req)
		if w.Code != http.StatusOK {
			t.Fatalf(
				"got status %d; want %d: %s",
				w.Code,
				http.StatusOK,
				w.Body,
			)
		}
		var res oauth.TokenResponse
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatalf("failed to decode token response: %v", err)
		}
		if res.AccessToken == "" {
			t.Error("missing access token")
		}
		if res.RefreshToken != "" {
			t.Error("machine-to-machine grant should not mint refresh tokens")
		}

		// The minted token introspects as active through the same server.
		form = url.Values{"token": {res.AccessToken}}
		req = httptest.NewRequest(
			http.MethodPost,
			"/oauth"+oauth.PathIntrospect,
			strings.NewReader(form.Encode()),
		)
		req.Header.Set(
			"Content-Type",
			"application/x-www-form-urlencoded",
		)
		req.SetBasicAuth(client.id.String(), "s3cret")

		w = do(req)
		if w.Code != http.StatusOK {
			t.Fatalf(
				"got status %d; want %d: %s",
				w.Code,
				http.StatusOK,
				w.Body,
			)
		}
		var intro oauth.IntrospectionResponse
		if err := json.Unmarshal(w.Body.Bytes(), &intro); err != nil {
			t.Fatalf("failed to decode introspection: %v", err)
		}
		if !intro.Active {
			t.Error("token should introspect as active")
		}
		if intro.Sub != client.id.String() {
			t.Errorf(
				"got sub %q; want the client itself (%s)",
				intro.Sub,
				client.id,
			)
		}
	})
}

// TestNewServer_ResolverValidation proves the construction-time seams: a
// delegated grant demands an owner resolver, and the session-bound endpoints
// demand a session resolver.
func TestNewServer_ResolverValidation(t *testing.T) {
	t.Parallel()

	key, err := jwk.Generate(jwa.ES256)
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}

	base := func() oauth.ServerConfig {
		return oauth.ServerConfig{
			Vault:   vault.New([]jwk.KeyPair{key}, rotor.Sequential),
			Clients: &m2mClientStore{client: &m2mClient{id: uuid.New()}},
			Tokens: oauth.TokenStores{
				AuthCodes: artifact.NewMap(
					func(c oauth.AuthCode) oauth.Digest { return c.Code },
				),
				RefreshTokens: artifact.NewMap(
					func(r oauth.RefreshToken) oauth.Digest { return r.Token },
				),
			},
			Issuer: "https://id.example.com",
		}
	}

	mustPanic := func(t *testing.T, fn func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Error("NewServer did not panic")
			}
		}()
		fn()
	}

	t.Run("delegated grant without owners", func(t *testing.T) {
		t.Parallel()
		mustPanic(t, func() {
			oauth.NewServer(base(), oauth.WithGrant(grant.RefreshToken()))
		})
	})

	t.Run("auth code grant without sessions", func(t *testing.T) {
		t.Parallel()
		cfg := base()
		cfg.Owners = func(
			context.Context,
			uuid.UUID,
		) (oauth.Owner, error) {
			return nil, nil
		}
		mustPanic(t, func() {
			oauth.NewServer(cfg, oauth.WithGrant(grant.AuthCode()))
		})
	})

	t.Run("client credentials alone needs neither", func(t *testing.T) {
		t.Parallel()
		s := oauth.NewServer(
			base(),
			oauth.WithGrant(grant.ClientCredentials()),
		)
		if !s.Supports(oauth.GrantTypeClientCredentials) {
			t.Error("grant not registered")
		}
	})
}
