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

package iam

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
	"uuid"

	"golang.org/x/time/rate"

	"github.com/deep-rent/nexus/net/router"
	"github.com/deep-rent/nexus/net/throttle"
	"github.com/deep-rent/nexus/sec/auth"
	"github.com/deep-rent/nexus/sec/iam/oauth"
	"github.com/deep-rent/nexus/sec/iam/oauth/grant"
	"github.com/deep-rent/nexus/sec/iam/oauth/pkce"
	"github.com/deep-rent/nexus/sec/jose/jwa"
	"github.com/deep-rent/nexus/sec/jose/jwk"
	"github.com/deep-rent/nexus/sec/jose/jwt"
	"github.com/deep-rent/nexus/sec/vault"
	"github.com/deep-rent/nexus/std/rotor"
)

const (
	testIssuer   = "https://id.example.com"
	testPrefix   = "/oauth"
	testRedirect = "https://app.example.com/callback"
)

// testEnv wires a fully mounted [Server] against in-memory fakes.
type testEnv struct {
	server   *Server
	router   *router.Router
	vault    vault.Vault
	clients  *fakeClientStore
	subjects *fakeSubjectStore
	stores   *fakeStores
	client   *fakeClient // confidential default client
	public   *fakeClient // public client without a secret
	subject  *fakeSubject
	now      time.Time
}

func newTestEnv(t *testing.T, opts ...Option) *testEnv {
	t.Helper()

	key, err := jwk.Generate(jwa.ES256)
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}
	v := vault.New([]jwk.KeyPair{key}, rotor.Sequential)

	allGrants := []oauth.GrantType{
		oauth.GrantTypeAuthorizationCode,
		oauth.GrantTypeClientCredentials,
		oauth.GrantTypeRefreshToken,
		oauth.GrantTypeDeviceCode,
	}

	env := &testEnv{
		vault: v,
		now:   time.Unix(1_752_000_000, 0),
		client: &fakeClient{
			id:        uuid.New(),
			secret:    "s3cret",
			audience:  []string{"https://api.example.com"},
			redirects: []string{testRedirect},
			grants:    allGrants,
			scopes:    []string{"read", "write"},
		},
		public: &fakeClient{
			id:        uuid.New(),
			public:    true,
			redirects: []string{testRedirect},
			grants:    allGrants,
			scopes:    []string{"read"},
		},
		subject: &fakeSubject{
			id:       uuid.New(),
			username: "alice",
			roles:    []string{"admin"},
		},
	}

	env.clients = &fakeClientStore{clients: map[uuid.UUID]oauth.Client{
		env.client.id: env.client,
		env.public.id: env.public,
	}}

	env.subjects = newFakeSubjectStore()
	env.subjects.subjects[env.subject.id] = env.subject
	env.subjects.passwords["alice"] = "wonderland"
	env.subjects.usernames["alice"] = env.subject.id

	env.stores = newFakeStores()

	cfg := Config{
		Vault:            v,
		Clients:          env.clients,
		Stores:           env.stores.Stores,
		Subjects:         env.subjects,
		Issuer:           testIssuer,
		LoginTerminalURI: "https://app.example.com/login",
		LoginRedirectURI: "https://app.example.com/dashboard",
		VerificationURI:  "https://app.example.com/device",
		Logger:           discardLogger(),
	}

	opts = append([]Option{
		WithGrant(grant.AuthCode()),
		WithGrant(grant.ClientCredentials()),
		WithGrant(grant.RefreshToken()),
		WithGrant(grant.DeviceCode()),
		WithClock(func() time.Time { return env.now }),
	}, opts...)

	s := New(cfg, opts...)

	env.server = s
	env.router = router.New()
	s.Mount(env.router, testPrefix)

	return env
}

// withThrottle installs a throttle on the server under test. Production
// code sets [Config.Throttle]; this mirrors it without threading a config
// mutator through every call site. Options run before Mount, so the
// middleware is installed as usual.
func withThrottle(th *throttle.Throttle) Option {
	return func(s *Server) { s.throttle = th }
}

// withThrottlePenalty overrides the per-failure charge on the server under
// test, mirroring Config.ThrottlePenalty without threading a config mutator
// through every call site.
func withThrottlePenalty(n int) Option {
	return func(s *Server) { s.throttlePenalty = n }
}

func (env *testEnv) do(req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	return w
}

// postForm issues a form-encoded POST. A non-empty secret adds HTTP Basic
// client authentication for the given client.
func (env *testEnv) postForm(
	path string,
	form url.Values,
	client *fakeClient,
	secret string,
) *httptest.ResponseRecorder {
	if secret == "" && client != nil {
		form.Set("client_id", client.id.String())
	}
	req := httptest.NewRequest(
		http.MethodPost,
		testPrefix+path,
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if secret != "" {
		req.SetBasicAuth(client.id.String(), secret)
	}
	return env.do(req)
}

// login seeds a session for the default subject and returns the cookie.
func (env *testEnv) login() *http.Cookie {
	seedSession(env.stores, "session-key", env.subject.id, 0)
	return &http.Cookie{
		Name:  DefaultSessionCookieName,
		Value: "session-key",
	}
}

func decodeJSON[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("failed to decode response %q: %v", w.Body.String(), err)
	}
	return v
}

func (env *testEnv) verifyToken(t *testing.T, token string) *auth.Claims {
	t.Helper()
	verifier := jwt.NewVerifier[*auth.Claims](
		env.vault.Keys(),
		jwt.WithIssuers(testIssuer),
		jwt.WithClock(func() time.Time { return env.now }),
	)
	claims, err := verifier.Verify([]byte(token))
	if err != nil {
		t.Fatalf("failed to verify access token: %v", err)
	}
	return claims
}

func TestNewValidation(t *testing.T) {
	t.Parallel()

	key, err := jwk.Generate(jwa.ES256)
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}

	valid := Config{
		Vault:    vault.New([]jwk.KeyPair{key}, rotor.Sequential),
		Clients:  &fakeClientStore{},
		Stores:   newFakeStores().Stores,
		Subjects: newFakeSubjectStore(),
		Issuer:   testIssuer,
	}

	tests := []struct {
		name   string
		mutate func(*Config)
		opts   []Option
	}{
		{
			name:   "missing vault",
			mutate: func(c *Config) { c.Vault = nil },
		},
		{
			name:   "missing clients",
			mutate: func(c *Config) { c.Clients = nil },
		},
		{
			name:   "missing auth code store",
			mutate: func(c *Config) { c.Stores.AuthCodes = nil },
		},
		{
			name:   "missing refresh token store",
			mutate: func(c *Config) { c.Stores.RefreshTokens = nil },
		},
		{
			name:   "missing subjects",
			mutate: func(c *Config) { c.Subjects = nil },
		},
		{
			name:   "missing issuer",
			mutate: func(c *Config) { c.Issuer = "" },
		},
		{
			name:   "idp without login URIs",
			mutate: func(c *Config) {},
			opts: []Option{
				WithIdentityProvider("acme", &fakeIDP{}),
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

			cfg := valid
			tt.mutate(&cfg)
			New(cfg, tt.opts...)
		})
	}

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		if s := New(valid); s == nil {
			t.Error("should have returned a server")
		}
	})
}

func TestWellKnown(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)

	w := env.do(httptest.NewRequest(
		http.MethodGet,
		testPrefix+oauth.PathWellKnown,
		nil,
	))

	if w.Code != http.StatusOK {
		t.Fatalf("got status %d; want %d", w.Code, http.StatusOK)
	}

	meta := decodeJSON[oauth.ServerMetadata](t, w)

	base := testIssuer + testPrefix
	if meta.Issuer != testIssuer {
		t.Errorf("got issuer %q; want %q", meta.Issuer, testIssuer)
	}
	if want := base + oauth.PathToken; meta.TokenEndpoint != want {
		t.Errorf("got token endpoint %q; want %q", meta.TokenEndpoint, want)
	}
	if want := base + oauth.PathAuthorize; meta.AuthorizationEndpoint != want {
		t.Errorf(
			"got authorization endpoint %q; want %q",
			meta.AuthorizationEndpoint,
			want,
		)
	}
	if want := base + oauth.PathDeviceAuthorization; meta.DeviceAuthorizationEndpoint != want {
		t.Errorf(
			"got device authorization endpoint %q; want %q",
			meta.DeviceAuthorizationEndpoint,
			want,
		)
	}
	wantGrants := []string{
		string(oauth.GrantTypeAuthorizationCode),
		string(oauth.GrantTypeClientCredentials),
		string(oauth.GrantTypeRefreshToken),
		string(oauth.GrantTypeDeviceCode),
	}
	slices.Sort(wantGrants)
	if !slices.Equal(meta.GrantTypesSupported, wantGrants) {
		t.Errorf(
			"got grant types %v; want %v",
			meta.GrantTypesSupported,
			wantGrants,
		)
	}
	if !slices.Equal(meta.ResponseTypesSupported, []string{"code"}) {
		t.Errorf(
			"got response types %v; want [code]",
			meta.ResponseTypesSupported,
		)
	}
	if !slices.Contains(meta.CodeChallengeMethodsSupported, pkce.MethodS256) {
		t.Errorf(
			"code challenge methods %v should include %q",
			meta.CodeChallengeMethodsSupported,
			pkce.MethodS256,
		)
	}

	// RFC 8414 Section 3: the metadata must also be served at the location
	// clients derive from the issuer (well-known path inserted at the root).
	w = env.do(httptest.NewRequest(http.MethodGet, oauth.PathWellKnown, nil))
	if w.Code != http.StatusOK {
		t.Fatalf(
			"got status %d at root well-known location; want %d",
			w.Code,
			http.StatusOK,
		)
	}
	if root := decodeJSON[oauth.ServerMetadata](
		t,
		w,
	); root.Issuer != testIssuer {
		t.Errorf("got issuer %q; want %q", root.Issuer, testIssuer)
	}
}

func TestRefreshScopePreserved(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	seed(t, env.stores.refreshTokens, oauth.RefreshToken{
		Token:     newDigest("rt-1"),
		ClientID:  env.client.id,
		SubjectID: env.subject.id,
		Scope:     "read write",
		ExpiresAt: env.now.Add(time.Hour).Unix(),
	})

	// RFC 6749 Section 6: narrowing applies to the issued access token only;
	// the rotated refresh token must keep the original grant scope.
	w := env.postForm(oauth.PathToken, url.Values{
		"grant_type":    {string(oauth.GrantTypeRefreshToken)},
		"refresh_token": {"rt-1"},
		"scope":         {"read"},
	}, env.client, "s3cret")

	if w.Code != http.StatusOK {
		t.Fatalf("got status %d; want %d: %s", w.Code, http.StatusOK, w.Body)
	}

	res := decodeJSON[oauth.TokenResponse](t, w)
	if res.Scope != "read" {
		t.Errorf("got access token scope %q; want %q", res.Scope, "read")
	}

	stored, ok, _ := env.stores.refreshTokens.Get(
		t.Context(),
		newDigest(res.RefreshToken),
	)
	if !ok {
		t.Fatal("rotated refresh token should have been stored")
	}
	if stored.Scope != "read write" {
		t.Errorf(
			"got rotated refresh token scope %q; want the original %q",
			stored.Scope,
			"read write",
		)
	}
}

func TestTokenClientCredentials(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)

	form := url.Values{
		"grant_type": {string(oauth.GrantTypeClientCredentials)},
		"scope":      {"read"},
	}
	w := env.postForm(oauth.PathToken, form, env.client, "s3cret")

	if w.Code != http.StatusOK {
		t.Fatalf("got status %d; want %d: %s", w.Code, http.StatusOK, w.Body)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("got Cache-Control %q; want %q", got, "no-store")
	}

	res := decodeJSON[oauth.TokenResponse](t, w)
	if res.TokenType != auth.Scheme {
		t.Errorf("got token type %q; want %q", res.TokenType, auth.Scheme)
	}
	if res.ExpiresIn != 3600 {
		t.Errorf("got expires_in %d; want 3600", res.ExpiresIn)
	}
	if res.RefreshToken != "" {
		t.Error("client credentials grant should not issue a refresh token")
	}

	claims := env.verifyToken(t, res.AccessToken)
	if claims.Azp != env.client.id.String() {
		t.Errorf("got azp %v; want %v", claims.Azp, env.client.id)
	}
	if claims.Sub != env.client.id.String() {
		t.Errorf("got sub %v; want the client %v", claims.Sub, env.client.id)
	}
	if got := claims.Scope.String(); got != "read" {
		t.Errorf("got scope %q; want %q", got, "read")
	}
	if !slices.Equal(claims.Aud, env.client.audience) {
		t.Errorf("got aud %v; want %v", claims.Aud, env.client.audience)
	}
}

func TestTokenErrors(t *testing.T) {
	t.Parallel()

	form := func(grant string) url.Values {
		return url.Values{"grant_type": {grant}}
	}

	t.Run("wrong secret", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)

		w := env.postForm(
			oauth.PathToken,
			form(string(oauth.GrantTypeClientCredentials)),
			env.client,
			"wrong",
		)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusUnauthorized)
		}
		if got := w.Header().
			Get("WWW-Authenticate"); !strings.HasPrefix(
			got,
			"Basic",
		) {
			t.Errorf("got WWW-Authenticate %q; want a Basic challenge", got)
		}
		res := decodeJSON[oauth.Error](t, w)
		if res.Code != oauth.ErrorCodeInvalidClient {
			t.Errorf("got error %q; want %q", res.Code, oauth.ErrorCodeInvalidClient)
		}
	})

	t.Run("conflicting auth methods", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)

		// RFC 6749 Section 2.3.1: a second credential (client_secret in the
		// body alongside HTTP Basic) constitutes a second auth method.
		f := form(string(oauth.GrantTypeClientCredentials))
		f.Set("client_secret", "s3cret")
		req := httptest.NewRequest(
			http.MethodPost,
			testPrefix+oauth.PathToken,
			strings.NewReader(f.Encode()),
		)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(env.client.id.String(), "s3cret")

		w := env.do(req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusBadRequest)
		}
		res := decodeJSON[oauth.Error](t, w)
		if res.Code != oauth.ErrorCodeInvalidRequest {
			t.Errorf("got error %q; want %q", res.Code, oauth.ErrorCodeInvalidRequest)
		}
	})

	t.Run("redundant client id with basic auth", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)

		// Many client libraries include client_id in the body even when
		// authenticating via HTTP Basic; a matching value is tolerated.
		f := form(string(oauth.GrantTypeClientCredentials))
		f.Set("client_id", env.client.id.String())
		req := httptest.NewRequest(
			http.MethodPost,
			testPrefix+oauth.PathToken,
			strings.NewReader(f.Encode()),
		)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(env.client.id.String(), "s3cret")

		w := env.do(req)
		if w.Code != http.StatusOK {
			t.Fatalf(
				"got status %d; want %d: %s",
				w.Code,
				http.StatusOK,
				w.Body,
			)
		}
	})

	t.Run("mismatched client id with basic auth", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)

		f := form(string(oauth.GrantTypeClientCredentials))
		f.Set("client_id", env.public.id.String())
		req := httptest.NewRequest(
			http.MethodPost,
			testPrefix+oauth.PathToken,
			strings.NewReader(f.Encode()),
		)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(env.client.id.String(), "s3cret")

		w := env.do(req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusBadRequest)
		}
	})

	t.Run("unsupported grant type", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)

		w := env.postForm(oauth.PathToken, form("password"), env.client, "s3cret")
		if w.Code != http.StatusBadRequest {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusBadRequest)
		}
		res := decodeJSON[oauth.Error](t, w)
		if res.Code != oauth.ErrorCodeUnsupportedGrantType {
			t.Errorf(
				"got error %q; want %q",
				res.Code,
				oauth.ErrorCodeUnsupportedGrantType,
			)
		}
	})

	t.Run("grant not allowed for client", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)
		env.client.grants = []oauth.GrantType{oauth.GrantTypeAuthorizationCode}

		w := env.postForm(
			oauth.PathToken,
			form(string(oauth.GrantTypeClientCredentials)),
			env.client,
			"s3cret",
		)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusBadRequest)
		}
		res := decodeJSON[oauth.Error](t, w)
		if res.Code != oauth.ErrorCodeUnauthorizedClient {
			t.Errorf(
				"got error %q; want %q",
				res.Code,
				oauth.ErrorCodeUnauthorizedClient,
			)
		}
	})
}

func TestAuthCodeFlow(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	cookie := env.login()

	verifier, err := pkce.Verifier(t.Context())
	if err != nil {
		t.Fatalf("failed to generate verifier: %v", err)
	}
	challenge, err := pkce.Challenge(verifier, pkce.MethodS256)
	if err != nil {
		t.Fatalf("failed to generate challenge: %v", err)
	}

	// Step 1: hit the authorization endpoint with an active session.
	q := url.Values{
		"client_id":             {env.client.id.String()},
		"redirect_uri":          {testRedirect},
		"response_type":         {"code"},
		"scope":                 {"read"},
		"state":                 {"xyz"},
		"code_challenge":        {challenge},
		"code_challenge_method": {pkce.MethodS256},
	}
	req := httptest.NewRequest(
		http.MethodGet,
		testPrefix+oauth.PathAuthorize+"?"+q.Encode(),
		nil,
	)
	req.AddCookie(cookie)

	w := env.do(req)
	if w.Code != http.StatusFound {
		t.Fatalf("got status %d; want %d: %s", w.Code, http.StatusFound, w.Body)
	}

	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("failed to parse redirect location: %v", err)
	}
	if got := loc.Query().Get("state"); got != "xyz" {
		t.Errorf("got state %q; want %q", got, "xyz")
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("missing code in redirect: %s", loc)
	}

	// Step 2: exchange the code for tokens.
	w = env.postForm(oauth.PathToken, url.Values{
		"grant_type":    {string(oauth.GrantTypeAuthorizationCode)},
		"code":          {code},
		"redirect_uri":  {testRedirect},
		"code_verifier": {verifier},
	}, env.client, "s3cret")

	if w.Code != http.StatusOK {
		t.Fatalf("got status %d; want %d: %s", w.Code, http.StatusOK, w.Body)
	}

	res := decodeJSON[oauth.TokenResponse](t, w)
	if res.RefreshToken == "" {
		t.Fatal("authorization code grant should issue a refresh token")
	}

	claims := env.verifyToken(t, res.AccessToken)
	if claims.Sub != env.subject.id.String() {
		t.Errorf("got sub %v; want %v", claims.Sub, env.subject.id)
	}
	if claims.Azp != env.client.id.String() {
		t.Errorf("got azp %v; want %v", claims.Azp, env.client.id)
	}
	if !slices.Equal(claims.Roles, []string{"admin"}) {
		t.Errorf("got roles %v; want [admin]", claims.Roles)
	}

	// Step 3: rotate the refresh token.
	w = env.postForm(oauth.PathToken, url.Values{
		"grant_type":    {string(oauth.GrantTypeRefreshToken)},
		"refresh_token": {res.RefreshToken},
	}, env.client, "s3cret")

	if w.Code != http.StatusOK {
		t.Fatalf("got status %d; want %d: %s", w.Code, http.StatusOK, w.Body)
	}

	next := decodeJSON[oauth.TokenResponse](t, w)
	if next.RefreshToken == "" || next.RefreshToken == res.RefreshToken {
		t.Error("refresh token should have been rotated")
	}

	// Step 4: the old refresh token must be unusable.
	w = env.postForm(oauth.PathToken, url.Values{
		"grant_type":    {string(oauth.GrantTypeRefreshToken)},
		"refresh_token": {res.RefreshToken},
	}, env.client, "s3cret")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("got status %d; want %d", w.Code, http.StatusBadRequest)
	}
	if res := decodeJSON[oauth.Error](t, w); res.Code != oauth.ErrorCodeInvalidGrant {
		t.Errorf("got error %q; want %q", res.Code, oauth.ErrorCodeInvalidGrant)
	}
}

func TestAuthorizeErrors(t *testing.T) {
	t.Parallel()

	authorizeURL := func(q url.Values) string {
		return testPrefix + oauth.PathAuthorize + "?" + q.Encode()
	}

	t.Run("unauthenticated resource owner", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)

		q := url.Values{
			"client_id":             {env.client.id.String()},
			"redirect_uri":          {testRedirect},
			"response_type":         {"code"},
			"code_challenge":        {"challenge"},
			"code_challenge_method": {pkce.MethodPlain},
		}
		w := env.do(httptest.NewRequest(http.MethodGet, authorizeURL(q), nil))

		if w.Code != http.StatusFound {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusFound)
		}
		loc, err := url.Parse(w.Header().Get("Location"))
		if err != nil {
			t.Fatalf("failed to parse redirect location: %v", err)
		}
		if got := loc.Query().Get("error"); got != oauth.ErrorCodeAccessDenied {
			t.Errorf("got error %q; want %q", got, oauth.ErrorCodeAccessDenied)
		}
	})

	t.Run("unlisted redirect uri", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)

		q := url.Values{
			"client_id":     {env.client.id.String()},
			"redirect_uri":  {"https://evil.example.com/callback"},
			"response_type": {"code"},
		}
		w := env.do(httptest.NewRequest(http.MethodGet, authorizeURL(q), nil))

		// The user-agent must NOT be redirected to an unverified URI.
		if w.Code != http.StatusBadRequest {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusBadRequest)
		}
		if res := decodeJSON[oauth.Error](t, w); res.Code != oauth.ErrorCodeInvalidRequest {
			t.Errorf("got error %q; want %q", res.Code, oauth.ErrorCodeInvalidRequest)
		}
	})

	t.Run("missing pkce challenge", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)

		q := url.Values{
			"client_id":     {env.client.id.String()},
			"redirect_uri":  {testRedirect},
			"response_type": {"code"},
		}
		w := env.do(httptest.NewRequest(http.MethodGet, authorizeURL(q), nil))

		if w.Code != http.StatusFound {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusFound)
		}
		loc, err := url.Parse(w.Header().Get("Location"))
		if err != nil {
			t.Fatalf("failed to parse redirect location: %v", err)
		}
		if got := loc.Query().Get("error"); got != oauth.ErrorCodeInvalidRequest {
			t.Errorf("got error %q; want %q", got, oauth.ErrorCodeInvalidRequest)
		}
	})
}

func TestIntrospect(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)

	// Mint a token to introspect.
	w := env.postForm(oauth.PathToken, url.Values{
		"grant_type": {string(oauth.GrantTypeClientCredentials)},
		"scope":      {"read"},
	}, env.client, "s3cret")
	if w.Code != http.StatusOK {
		t.Fatalf("failed to mint token: %s", w.Body)
	}
	token := decodeJSON[oauth.TokenResponse](t, w).AccessToken

	t.Run("active token", func(t *testing.T) {
		w := env.postForm(oauth.PathIntrospect, url.Values{
			"token": {token},
		}, env.client, "s3cret")

		if w.Code != http.StatusOK {
			t.Fatalf(
				"got status %d; want %d: %s",
				w.Code,
				http.StatusOK,
				w.Body,
			)
		}
		res := decodeJSON[oauth.IntrospectionResponse](t, w)
		if !res.Active {
			t.Fatal("token should be active")
		}
		if res.ClientID != env.client.id.String() {
			t.Errorf("got client_id %q; want %q", res.ClientID, env.client.id)
		}
		if res.Sub != env.client.id.String() {
			t.Errorf("got sub %q; want %q", res.Sub, env.client.id)
		}
		if res.Iat != env.now.Unix() {
			t.Errorf("got iat %d; want %d", res.Iat, env.now.Unix())
		}
		if want := env.now.Add(time.Hour).Unix(); res.Exp != want {
			t.Errorf("got exp %d; want %d", res.Exp, want)
		}
	})

	t.Run("garbage token", func(t *testing.T) {
		w := env.postForm(oauth.PathIntrospect, url.Values{
			"token": {"garbage"},
		}, env.client, "s3cret")

		if w.Code != http.StatusOK {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusOK)
		}
		if res := decodeJSON[oauth.IntrospectionResponse](t, w); res.Active {
			t.Error("garbage token should be inactive")
		}
	})

	t.Run("public client rejected", func(t *testing.T) {
		w := env.postForm(oauth.PathIntrospect, url.Values{
			"token": {token},
		}, env.public, "")

		if w.Code != http.StatusForbidden {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusForbidden)
		}
		res := decodeJSON[oauth.Error](t, w)
		if res.Code != oauth.ErrorCodeUnauthorizedClient {
			t.Errorf(
				"got error %q; want %q",
				res.Code,
				oauth.ErrorCodeUnauthorizedClient,
			)
		}
	})
}

func TestRevoke(t *testing.T) {
	t.Parallel()

	t.Run("own token", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)
		seed(t, env.stores.refreshTokens, oauth.RefreshToken{
			Token:     newDigest("token-1"),
			ClientID:  env.client.id,
			ExpiresAt: env.now.Add(time.Hour).Unix(),
		})

		w := env.postForm(oauth.PathRevoke, url.Values{
			"token": {"token-1"},
		}, env.client, "s3cret")

		if w.Code != http.StatusOK {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusOK)
		}
		if _, found, _ := env.stores.refreshTokens.Get(
			t.Context(),
			newDigest("token-1"),
		); found {
			t.Error("refresh token should have been revoked")
		}
	})

	t.Run("foreign token", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)
		seed(t, env.stores.refreshTokens, oauth.RefreshToken{
			Token:     newDigest("token-2"),
			ClientID:  uuid.New(), // some other client
			ExpiresAt: env.now.Add(time.Hour).Unix(),
		})

		w := env.postForm(oauth.PathRevoke, url.Values{
			"token": {"token-2"},
		}, env.client, "s3cret")

		// RFC 7009: respond 200 without leaking token existence.
		if w.Code != http.StatusOK {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusOK)
		}
		if _, found, _ := env.stores.refreshTokens.Get(
			t.Context(),
			newDigest("token-2"),
		); !found {
			t.Error("foreign refresh token should not have been revoked")
		}
	})
}

func TestDeviceFlow(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)

	// Step 1: the device requests a device and user code pair.
	w := env.postForm(oauth.PathDeviceAuthorization, url.Values{
		"scope": {"read"},
	}, env.client, "s3cret")

	if w.Code != http.StatusOK {
		t.Fatalf("got status %d; want %d: %s", w.Code, http.StatusOK, w.Body)
	}

	res := decodeJSON[oauth.DeviceAuthorizationResponse](t, w)
	if res.DeviceCode == "" || res.UserCode == "" {
		t.Fatalf("incomplete device authorization response: %+v", res)
	}
	if res.Interval != 5 {
		t.Errorf("got interval %d; want 5", res.Interval)
	}
	if want := "https://app.example.com/device"; res.VerificationURI != want {
		t.Errorf("got verification uri %q; want %q", res.VerificationURI, want)
	}
	if !strings.Contains(res.VerificationURIComplete, "user_code=") {
		t.Errorf(
			"verification_uri_complete %q should embed the user code",
			res.VerificationURIComplete,
		)
	}

	poll := func() *httptest.ResponseRecorder {
		return env.postForm(oauth.PathToken, url.Values{
			"grant_type":  {string(oauth.GrantTypeDeviceCode)},
			"device_code": {res.DeviceCode},
		}, env.client, "s3cret")
	}

	// Step 2: polling before approval yields authorization_pending.
	w = poll()
	if w.Code != http.StatusBadRequest {
		t.Fatalf("got status %d; want %d", w.Code, http.StatusBadRequest)
	}
	if e := decodeJSON[oauth.Error](t, w); e.Code != oauth.ErrorCodeAuthorizationPending {
		t.Fatalf(
			"got error %q; want %q",
			e.Code,
			oauth.ErrorCodeAuthorizationPending,
		)
	}

	// Step 3: the resource owner approves the request. The user code is
	// entered sloppily to exercise normalization.
	body := `{"user_code":"` +
		strings.ToLower(strings.ReplaceAll(res.UserCode, "-", " ")) +
		`","action":"approve"}`
	req := httptest.NewRequest(
		http.MethodPost,
		testPrefix+oauth.PathDeviceVerify,
		strings.NewReader(body),
	)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(env.login())

	w = env.do(req)
	if w.Code != http.StatusNoContent {
		t.Fatalf(
			"got status %d; want %d: %s",
			w.Code,
			http.StatusNoContent,
			w.Body,
		)
	}

	stored, _, _ := env.stores.deviceCodes.Get(
		t.Context(),
		newDigest(res.DeviceCode),
	)
	if stored.Status != oauth.DeviceCodeStatusAuthorized {
		t.Fatalf(
			"got status %q; want %q",
			stored.Status,
			oauth.DeviceCodeStatusAuthorized,
		)
	}
	if stored.SubjectID != env.subject.id {
		t.Fatalf("got subject %v; want %v", stored.SubjectID, env.subject.id)
	}

	// Step 4: the device polls again after the interval and receives tokens.
	env.now = env.now.Add(6 * time.Second)

	w = poll()
	if w.Code != http.StatusOK {
		t.Fatalf("got status %d; want %d: %s", w.Code, http.StatusOK, w.Body)
	}

	token := decodeJSON[oauth.TokenResponse](t, w)
	claims := env.verifyToken(t, token.AccessToken)
	if claims.Sub != env.subject.id.String() {
		t.Errorf("got sub %v; want %v", claims.Sub, env.subject.id)
	}
	if _, found, _ := env.stores.deviceCodes.Get(
		t.Context(),
		newDigest(res.DeviceCode),
	); found {
		t.Error("device code should have been deleted after issuance")
	}
}

func TestDeviceVerifyErrors(t *testing.T) {
	t.Parallel()

	verify := func(
		env *testEnv,
		body string,
		cookie *http.Cookie,
	) *httptest.ResponseRecorder {
		req := httptest.NewRequest(
			http.MethodPost,
			testPrefix+oauth.PathDeviceVerify,
			strings.NewReader(body),
		)
		req.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			req.AddCookie(cookie)
		}
		return env.do(req)
	}

	t.Run("unauthenticated", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)

		w := verify(env, `{"user_code":"BCDF-GHJK","action":"approve"}`, nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusUnauthorized)
		}
	})

	t.Run("unknown user code", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)

		w := verify(
			env,
			`{"user_code":"BCDF-GHJK","action":"approve"}`,
			env.login(),
		)
		if w.Code != http.StatusNotFound {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusNotFound)
		}
	})

	t.Run("already decided", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)
		seed(t, env.stores.deviceCodes, oauth.DeviceCode{
			DeviceCode: newDigest("device-1"),
			UserCode:   newDigest("BCDF-GHJK"),
			ClientID:   env.client.id,
			Status:     oauth.DeviceCodeStatusAuthorized,
			ExpiresAt:  env.now.Add(10 * time.Minute).Unix(),
		})

		w := verify(
			env,
			`{"user_code":"BCDF-GHJK","action":"deny"}`,
			env.login(),
		)
		if w.Code != http.StatusConflict {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusConflict)
		}
	})

	t.Run("invalid action", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)

		w := verify(
			env,
			`{"user_code":"BCDF-GHJK","action":"maybe"}`,
			env.login(),
		)
		if w.Code != http.StatusBadRequest &&
			w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("got status %d; want a validation failure", w.Code)
		}
	})
}

// failingSource simulates an exhausted entropy source: every artifact the
// server tries to mint fails.
type failingSource struct{}

func (failingSource) Read(context.Context, []byte) error {
	return errors.New("boom")
}

// wantServerError asserts an opaque 500 response carrying a trace ID.
func wantServerError(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusInternalServerError {
		t.Fatalf(
			"got status %d; want %d: %s",
			w.Code,
			http.StatusInternalServerError,
			w.Body,
		)
	}
	res := decodeJSON[oauth.Error](t, w)
	if res.Code != oauth.ErrorCodeServerError {
		t.Errorf("got error %q; want %q", res.Code, oauth.ErrorCodeServerError)
	}
	if res.ID == "" {
		t.Error("missing trace ID on internal error")
	}
}

func TestInternalFailures(t *testing.T) {
	t.Parallel()

	t.Run("client lookup failure", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)
		env.clients.err = errors.New("db down")

		w := env.postForm(oauth.PathToken, url.Values{
			"grant_type": {string(oauth.GrantTypeClientCredentials)},
		}, env.client, "s3cret")

		wantServerError(t, w)
	})

	t.Run("session store failure during exchange", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)
		env.stores.setErr(errors.New("db down"))

		w := env.postForm(oauth.PathToken, url.Values{
			"grant_type":    {string(oauth.GrantTypeRefreshToken)},
			"refresh_token": {"token-1"},
		}, env.client, "s3cret")

		wantServerError(t, w)
	})

	t.Run("auth code generation failure", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t, WithNonceSource(failingSource{}))

		q := url.Values{
			"client_id":             {env.client.id.String()},
			"redirect_uri":          {testRedirect},
			"response_type":         {"code"},
			"code_challenge":        {"challenge"},
			"code_challenge_method": {pkce.MethodPlain},
		}
		req := httptest.NewRequest(
			http.MethodGet,
			testPrefix+oauth.PathAuthorize+"?"+q.Encode(),
			nil,
		)
		req.AddCookie(env.login())

		wantServerError(t, env.do(req))
	})

	t.Run("refresh token generation failure", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t, WithNonceSource(failingSource{}))
		seed(t, env.stores.refreshTokens, oauth.RefreshToken{
			Token:     newDigest("rt-1"),
			ClientID:  env.client.id,
			SubjectID: env.subject.id,
			Scope:     "read",
			ExpiresAt: env.now.Add(time.Hour).Unix(),
		})

		w := env.postForm(oauth.PathToken, url.Values{
			"grant_type":    {string(oauth.GrantTypeRefreshToken)},
			"refresh_token": {"rt-1"},
		}, env.client, "s3cret")

		wantServerError(t, w)
	})

	t.Run("session key generation failure", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t, WithNonceSource(failingSource{}))

		w := postJSON(
			env,
			PathLogin,
			`{"username":"alice","password":"wonderland"}`,
		)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf(
				"got status %d; want %d",
				w.Code,
				http.StatusInternalServerError,
			)
		}
	})

	t.Run("device authorization generation failure", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t, WithNonceSource(failingSource{}))

		w := env.postForm(
			oauth.PathDeviceAuthorization,
			url.Values{},
			env.client,
			"s3cret",
		)

		wantServerError(t, w)
	})

	t.Run("state generation failure", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(
			t,
			WithIdentityProvider("acme", &fakeIDP{}),
			WithNonceSource(failingSource{}),
		)

		w := env.do(httptest.NewRequest(
			http.MethodGet,
			testPrefix+"/login/acme",
			nil,
		))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf(
				"got status %d; want %d",
				w.Code,
				http.StatusInternalServerError,
			)
		}
	})

	t.Run("subject lookup failure during login", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)
		env.subjects.err = errors.New("db down")

		w := postJSON(
			env,
			PathLogin,
			`{"username":"alice","password":"wonderland"}`,
		)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf(
				"got status %d; want %d",
				w.Code,
				http.StatusInternalServerError,
			)
		}
	})

	t.Run("subject lookup failure during verification", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)
		cookie := env.login()
		env.subjects.err = errors.New("db down")

		req := httptest.NewRequest(
			http.MethodPost,
			testPrefix+oauth.PathDeviceVerify,
			strings.NewReader(`{"user_code":"BCDF-GHJK","action":"deny"}`),
		)
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)

		w := env.do(req)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf(
				"got status %d; want %d",
				w.Code,
				http.StatusInternalServerError,
			)
		}
	})
}

func TestThrottleIntegration(t *testing.T) {
	t.Parallel()

	// newThrottled builds an environment whose allowance tolerates exactly
	// two failed attempts before locking out.
	newThrottled := func(t *testing.T, now *time.Time) *testEnv {
		t.Helper()
		return newTestEnv(t,
			withThrottle(throttle.New(throttle.Config{
				Rate:  rate.Limit(1),
				Burst: 10,
				Clock: func() time.Time { return *now },
			})),
			withThrottlePenalty(5),
		)
	}

	t.Run("client secret guessing locks out", func(t *testing.T) {
		t.Parallel()
		now := time.Unix(1_752_000_000, 0)
		env := newThrottled(t, &now)

		form := func() url.Values {
			return url.Values{
				"grant_type": {string(oauth.GrantTypeClientCredentials)},
			}
		}

		// Two wrong secrets are answered with the usual rejection.
		for i := range 2 {
			w := env.postForm(oauth.PathToken, form(), env.client, "wrong")
			if w.Code != http.StatusUnauthorized {
				t.Fatalf(
					"attempt %d: got status %d; want %d",
					i,
					w.Code,
					http.StatusUnauthorized,
				)
			}
		}

		// The third is locked out before the secret is even considered.
		w := env.postForm(oauth.PathToken, form(), env.client, "wrong")
		if w.Code != http.StatusTooManyRequests {
			t.Fatalf(
				"got status %d; want %d",
				w.Code,
				http.StatusTooManyRequests,
			)
		}
		if got := w.Header().Get("Retry-After"); got == "" {
			t.Error("missing Retry-After header")
		}
		if res := decodeJSON[oauth.Error](t, w); res.Code != oauth.ErrorCodeSlowDown {
			t.Errorf("got error %q; want %q", res.Code, oauth.ErrorCodeSlowDown)
		}

		// Even the correct secret is refused while the lockout stands.
		w = env.postForm(oauth.PathToken, form(), env.client, "s3cret")
		if w.Code != http.StatusTooManyRequests {
			t.Fatalf(
				"got status %d; want %d during lockout",
				w.Code,
				http.StatusTooManyRequests,
			)
		}

		// Once the allowance recovers, the correct secret works again.
		now = now.Add(time.Minute)
		w = env.postForm(oauth.PathToken, form(), env.client, "s3cret")
		if w.Code != http.StatusOK {
			t.Fatalf(
				"got status %d; want %d after recovery: %s",
				w.Code,
				http.StatusOK,
				w.Body,
			)
		}
	})

	t.Run("successful auth clears the penalty", func(t *testing.T) {
		t.Parallel()
		now := time.Unix(1_752_000_000, 0)
		env := newThrottled(t, &now)

		form := url.Values{
			"grant_type": {string(oauth.GrantTypeClientCredentials)},
		}

		// One failure, then a success, then two more failures: the success
		// must have reset the count, so the third failure is still answered
		// normally rather than locked out.
		env.postForm(oauth.PathToken, form, env.client, "wrong")
		if w := env.postForm(
			oauth.PathToken,
			form,
			env.client,
			"s3cret",
		); w.Code != http.StatusOK {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusOK)
		}

		for i := range 2 {
			w := env.postForm(oauth.PathToken, form, env.client, "wrong")
			if w.Code != http.StatusUnauthorized {
				t.Fatalf(
					"attempt %d: got status %d; want %d",
					i,
					w.Code,
					http.StatusUnauthorized,
				)
			}
		}
	})

	t.Run("password guessing locks out per account", func(t *testing.T) {
		t.Parallel()
		now := time.Unix(1_752_000_000, 0)
		env := newThrottled(t, &now)

		wrong := `{"username":"alice","password":"nope"}`

		for i := range 2 {
			if w := postJSON(
				env,
				PathLogin,
				wrong,
			); w.Code != http.StatusUnauthorized {
				t.Fatalf(
					"attempt %d: got status %d; want %d",
					i,
					w.Code,
					http.StatusUnauthorized,
				)
			}
		}

		w := postJSON(env, PathLogin, wrong)
		if w.Code != http.StatusTooManyRequests {
			t.Fatalf(
				"got status %d; want %d",
				w.Code,
				http.StatusTooManyRequests,
			)
		}

		// Case variations must not buy a fresh allowance.
		w = postJSON(env, PathLogin, `{"username":"ALICE","password":"nope"}`)
		if w.Code != http.StatusTooManyRequests {
			t.Errorf(
				"got status %d; want %d for a case variation",
				w.Code,
				http.StatusTooManyRequests,
			)
		}

		// A different account is unaffected.
		w = postJSON(env, PathLogin, `{"username":"bob","password":"nope"}`)
		if w.Code != http.StatusUnauthorized {
			t.Errorf(
				"got status %d; want %d for a different account",
				w.Code,
				http.StatusUnauthorized,
			)
		}
	})

	t.Run("user code guessing locks out", func(t *testing.T) {
		t.Parallel()
		now := time.Unix(1_752_000_000, 0)
		env := newThrottled(t, &now)
		cookie := env.login()

		guess := func() *httptest.ResponseRecorder {
			req := httptest.NewRequest(
				http.MethodPost,
				testPrefix+oauth.PathDeviceVerify,
				strings.NewReader(
					`{"user_code":"BCDF-GHJK","action":"approve"}`,
				),
			)
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(cookie)
			return env.do(req)
		}

		for i := range 2 {
			if w := guess(); w.Code != http.StatusNotFound {
				t.Fatalf(
					"attempt %d: got status %d; want %d",
					i,
					w.Code,
					http.StatusNotFound,
				)
			}
		}

		if w := guess(); w.Code != http.StatusTooManyRequests {
			t.Fatalf(
				"got status %d; want %d",
				w.Code,
				http.StatusTooManyRequests,
			)
		}
	})

	t.Run("disabled by default", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)

		form := url.Values{
			"grant_type": {string(oauth.GrantTypeClientCredentials)},
		}
		for range 5 {
			w := env.postForm(oauth.PathToken, form, env.client, "wrong")
			if w.Code != http.StatusUnauthorized {
				t.Fatalf(
					"got status %d; want %d without a throttle",
					w.Code,
					http.StatusUnauthorized,
				)
			}
		}
	})
}
