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

package oauth

import (
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"uuid"

	"github.com/deep-rent/nexus/auth"
	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/pkce"
	"github.com/deep-rent/nexus/rotor"
	"github.com/deep-rent/nexus/router"
	"github.com/deep-rent/nexus/vault"
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
	sessions *fakeSessionStore
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

	allGrants := []GrantType{
		GrantTypeAuthorizationCode,
		GrantTypeClientCredentials,
		GrantTypeRefreshToken,
		GrantTypeDeviceCode,
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
			id:    uuid.New(),
			roles: []string{"admin"},
		},
	}

	env.clients = &fakeClientStore{clients: map[uuid.UUID]Client{
		env.client.id: env.client,
		env.public.id: env.public,
	}}

	env.subjects = newFakeSubjectStore()
	env.subjects.subjects[env.subject.id] = env.subject
	env.subjects.passwords["alice"] = "wonderland"
	env.subjects.usernames["alice"] = env.subject.id

	env.sessions = newFakeSessionStore()

	cfg := Config{
		Vault:            v,
		Clients:          env.clients,
		Sessions:         env.sessions,
		Subjects:         env.subjects,
		Issuer:           testIssuer,
		LoginTerminalURI: "https://app.example.com/login",
		LoginRedirectURI: "https://app.example.com/dashboard",
		VerificationURI:  "https://app.example.com/device",
		Logger:           discardLogger(),
	}

	opts = append([]Option{
		WithGrant(AuthCodeGrant()),
		WithGrant(ClientCredentialsGrant()),
		WithGrant(RefreshTokenGrant()),
		WithGrant(DeviceCodeGrant()),
		WithClock(func() time.Time { return env.now }),
	}, opts...)

	s, err := New(cfg, opts...)
	if err != nil {
		t.Fatalf("failed to construct server: %v", err)
	}

	env.server = s
	env.router = router.New()
	s.Mount(env.router, testPrefix)

	return env
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
	env.subjects.sessions["session-key"] = env.subject.id
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
		Sessions: newFakeSessionStore(),
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
			name:   "missing sessions",
			mutate: func(c *Config) { c.Sessions = nil },
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

			cfg := valid
			tt.mutate(&cfg)
			if _, err := New(cfg, tt.opts...); err == nil {
				t.Error("should have returned a configuration error")
			}
		})
	}

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		if _, err := New(valid); err != nil {
			t.Errorf("should not have returned an error: %v", err)
		}
	})
}

func TestWellKnown(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)

	w := env.do(httptest.NewRequest(
		http.MethodGet,
		testPrefix+PathWellKnown,
		nil,
	))

	if w.Code != http.StatusOK {
		t.Fatalf("got status %d; want %d", w.Code, http.StatusOK)
	}

	meta := decodeJSON[AuthorizationServerMetadata](t, w)

	base := testIssuer + testPrefix
	if meta.Issuer != testIssuer {
		t.Errorf("got issuer %q; want %q", meta.Issuer, testIssuer)
	}
	if want := base + PathToken; meta.TokenEndpoint != want {
		t.Errorf("got token endpoint %q; want %q", meta.TokenEndpoint, want)
	}
	if want := base + PathAuthorize; meta.AuthorizationEndpoint != want {
		t.Errorf(
			"got authorization endpoint %q; want %q",
			meta.AuthorizationEndpoint,
			want,
		)
	}
	if want := base + PathDeviceAuthorization; meta.DeviceAuthorizationEndpoint != want {
		t.Errorf(
			"got device authorization endpoint %q; want %q",
			meta.DeviceAuthorizationEndpoint,
			want,
		)
	}
	wantGrants := []string{
		string(GrantTypeAuthorizationCode),
		string(GrantTypeClientCredentials),
		string(GrantTypeRefreshToken),
		string(GrantTypeDeviceCode),
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
}

func TestTokenClientCredentials(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)

	form := url.Values{
		"grant_type": {string(GrantTypeClientCredentials)},
		"scope":      {"read"},
	}
	w := env.postForm(PathToken, form, env.client, "s3cret")

	if w.Code != http.StatusOK {
		t.Fatalf("got status %d; want %d: %s", w.Code, http.StatusOK, w.Body)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("got Cache-Control %q; want %q", got, "no-store")
	}

	res := decodeJSON[TokenResponse](t, w)
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
	if claims.Azp != env.client.id {
		t.Errorf("got azp %v; want %v", claims.Azp, env.client.id)
	}
	if claims.Sub != env.client.id {
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
			PathToken,
			form(string(GrantTypeClientCredentials)),
			env.client,
			"wrong",
		)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusUnauthorized)
		}
		if got := w.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Basic") {
			t.Errorf("got WWW-Authenticate %q; want a Basic challenge", got)
		}
		res := decodeJSON[Error](t, w)
		if res.Code != ErrorCodeInvalidClient {
			t.Errorf("got error %q; want %q", res.Code, ErrorCodeInvalidClient)
		}
	})

	t.Run("conflicting auth methods", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)

		f := form(string(GrantTypeClientCredentials))
		f.Set("client_id", env.client.id.String())
		req := httptest.NewRequest(
			http.MethodPost,
			testPrefix+PathToken,
			strings.NewReader(f.Encode()),
		)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(env.client.id.String(), "s3cret")

		w := env.do(req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusBadRequest)
		}
		res := decodeJSON[Error](t, w)
		if res.Code != ErrorCodeInvalidRequest {
			t.Errorf("got error %q; want %q", res.Code, ErrorCodeInvalidRequest)
		}
	})

	t.Run("unsupported grant type", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)

		w := env.postForm(PathToken, form("password"), env.client, "s3cret")
		if w.Code != http.StatusBadRequest {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusBadRequest)
		}
		res := decodeJSON[Error](t, w)
		if res.Code != ErrorCodeUnsupportedGrantType {
			t.Errorf(
				"got error %q; want %q",
				res.Code,
				ErrorCodeUnsupportedGrantType,
			)
		}
	})

	t.Run("grant not allowed for client", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)
		env.client.grants = []GrantType{GrantTypeAuthorizationCode}

		w := env.postForm(
			PathToken,
			form(string(GrantTypeClientCredentials)),
			env.client,
			"s3cret",
		)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusBadRequest)
		}
		res := decodeJSON[Error](t, w)
		if res.Code != ErrorCodeUnauthorizedClient {
			t.Errorf(
				"got error %q; want %q",
				res.Code,
				ErrorCodeUnauthorizedClient,
			)
		}
	})
}

func TestAuthCodeFlow(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	cookie := env.login()

	verifier, err := pkce.Verifier(64)
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
		testPrefix+PathAuthorize+"?"+q.Encode(),
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
	w = env.postForm(PathToken, url.Values{
		"grant_type":    {string(GrantTypeAuthorizationCode)},
		"code":          {code},
		"redirect_uri":  {testRedirect},
		"code_verifier": {verifier},
	}, env.client, "s3cret")

	if w.Code != http.StatusOK {
		t.Fatalf("got status %d; want %d: %s", w.Code, http.StatusOK, w.Body)
	}

	res := decodeJSON[TokenResponse](t, w)
	if res.RefreshToken == "" {
		t.Fatal("authorization code grant should issue a refresh token")
	}

	claims := env.verifyToken(t, res.AccessToken)
	if claims.Sub != env.subject.id {
		t.Errorf("got sub %v; want %v", claims.Sub, env.subject.id)
	}
	if claims.Azp != env.client.id {
		t.Errorf("got azp %v; want %v", claims.Azp, env.client.id)
	}
	if !slices.Equal(claims.Roles, []string{"admin"}) {
		t.Errorf("got roles %v; want [admin]", claims.Roles)
	}

	// Step 3: rotate the refresh token.
	w = env.postForm(PathToken, url.Values{
		"grant_type":    {string(GrantTypeRefreshToken)},
		"refresh_token": {res.RefreshToken},
	}, env.client, "s3cret")

	if w.Code != http.StatusOK {
		t.Fatalf("got status %d; want %d: %s", w.Code, http.StatusOK, w.Body)
	}

	next := decodeJSON[TokenResponse](t, w)
	if next.RefreshToken == "" || next.RefreshToken == res.RefreshToken {
		t.Error("refresh token should have been rotated")
	}

	// Step 4: the old refresh token must be unusable.
	w = env.postForm(PathToken, url.Values{
		"grant_type":    {string(GrantTypeRefreshToken)},
		"refresh_token": {res.RefreshToken},
	}, env.client, "s3cret")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("got status %d; want %d", w.Code, http.StatusBadRequest)
	}
	if res := decodeJSON[Error](t, w); res.Code != ErrorCodeInvalidGrant {
		t.Errorf("got error %q; want %q", res.Code, ErrorCodeInvalidGrant)
	}
}

func TestAuthorizeErrors(t *testing.T) {
	t.Parallel()

	authorizeURL := func(q url.Values) string {
		return testPrefix + PathAuthorize + "?" + q.Encode()
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
		if got := loc.Query().Get("error"); got != ErrorCodeAccessDenied {
			t.Errorf("got error %q; want %q", got, ErrorCodeAccessDenied)
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
		if res := decodeJSON[Error](t, w); res.Code != ErrorCodeInvalidRequest {
			t.Errorf("got error %q; want %q", res.Code, ErrorCodeInvalidRequest)
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
		if got := loc.Query().Get("error"); got != ErrorCodeInvalidRequest {
			t.Errorf("got error %q; want %q", got, ErrorCodeInvalidRequest)
		}
	})
}

func TestIntrospect(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)

	// Mint a token to introspect.
	w := env.postForm(PathToken, url.Values{
		"grant_type": {string(GrantTypeClientCredentials)},
		"scope":      {"read"},
	}, env.client, "s3cret")
	if w.Code != http.StatusOK {
		t.Fatalf("failed to mint token: %s", w.Body)
	}
	token := decodeJSON[TokenResponse](t, w).AccessToken

	t.Run("active token", func(t *testing.T) {
		w := env.postForm(PathIntrospect, url.Values{
			"token": {token},
		}, env.client, "s3cret")

		if w.Code != http.StatusOK {
			t.Fatalf("got status %d; want %d: %s", w.Code, http.StatusOK, w.Body)
		}
		res := decodeJSON[IntrospectionResponse](t, w)
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
		w := env.postForm(PathIntrospect, url.Values{
			"token": {"garbage"},
		}, env.client, "s3cret")

		if w.Code != http.StatusOK {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusOK)
		}
		if res := decodeJSON[IntrospectionResponse](t, w); res.Active {
			t.Error("garbage token should be inactive")
		}
	})

	t.Run("public client rejected", func(t *testing.T) {
		w := env.postForm(PathIntrospect, url.Values{
			"token": {token},
		}, env.public, "")

		if w.Code != http.StatusForbidden {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusForbidden)
		}
		res := decodeJSON[Error](t, w)
		if res.Code != ErrorCodeUnauthorizedClient {
			t.Errorf(
				"got error %q; want %q",
				res.Code,
				ErrorCodeUnauthorizedClient,
			)
		}
	})
}

func TestRevoke(t *testing.T) {
	t.Parallel()

	t.Run("own token", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)
		env.sessions.refreshTokens["token-1"] = RefreshToken{
			Token:     "token-1",
			ClientID:  env.client.id,
			ExpiresAt: env.now.Add(time.Hour).Unix(),
		}

		w := env.postForm(PathRevoke, url.Values{
			"token": {"token-1"},
		}, env.client, "s3cret")

		if w.Code != http.StatusOK {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusOK)
		}
		if _, ok := env.sessions.refreshTokens["token-1"]; ok {
			t.Error("refresh token should have been revoked")
		}
	})

	t.Run("foreign token", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)
		env.sessions.refreshTokens["token-2"] = RefreshToken{
			Token:     "token-2",
			ClientID:  uuid.New(), // some other client
			ExpiresAt: env.now.Add(time.Hour).Unix(),
		}

		w := env.postForm(PathRevoke, url.Values{
			"token": {"token-2"},
		}, env.client, "s3cret")

		// RFC 7009: respond 200 without leaking token existence.
		if w.Code != http.StatusOK {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusOK)
		}
		if _, ok := env.sessions.refreshTokens["token-2"]; !ok {
			t.Error("foreign refresh token should not have been revoked")
		}
	})
}

func TestDeviceFlow(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)

	// Step 1: the device requests a device and user code pair.
	w := env.postForm(PathDeviceAuthorization, url.Values{
		"scope": {"read"},
	}, env.client, "s3cret")

	if w.Code != http.StatusOK {
		t.Fatalf("got status %d; want %d: %s", w.Code, http.StatusOK, w.Body)
	}

	res := decodeJSON[DeviceAuthorizationResponse](t, w)
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
		return env.postForm(PathToken, url.Values{
			"grant_type":  {string(GrantTypeDeviceCode)},
			"device_code": {res.DeviceCode},
		}, env.client, "s3cret")
	}

	// Step 2: polling before approval yields authorization_pending.
	w = poll()
	if w.Code != http.StatusBadRequest {
		t.Fatalf("got status %d; want %d", w.Code, http.StatusBadRequest)
	}
	if e := decodeJSON[Error](t, w); e.Code != ErrorCodeAuthorizationPending {
		t.Fatalf(
			"got error %q; want %q",
			e.Code,
			ErrorCodeAuthorizationPending,
		)
	}

	// Step 3: the resource owner approves the request. The user code is
	// entered sloppily to exercise normalization.
	body := `{"user_code":"` +
		strings.ToLower(strings.ReplaceAll(res.UserCode, "-", " ")) +
		`","action":"approve"}`
	req := httptest.NewRequest(
		http.MethodPost,
		testPrefix+PathDeviceVerify,
		strings.NewReader(body),
	)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(env.login())

	w = env.do(req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("got status %d; want %d: %s", w.Code, http.StatusNoContent, w.Body)
	}

	stored := env.sessions.deviceCodes[res.DeviceCode]
	if stored.Status != DeviceCodeStatusAuthorized {
		t.Fatalf("got status %q; want %q", stored.Status, DeviceCodeStatusAuthorized)
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

	token := decodeJSON[TokenResponse](t, w)
	claims := env.verifyToken(t, token.AccessToken)
	if claims.Sub != env.subject.id {
		t.Errorf("got sub %v; want %v", claims.Sub, env.subject.id)
	}
	if _, ok := env.sessions.deviceCodes[res.DeviceCode]; ok {
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
			testPrefix+PathDeviceVerify,
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
		env.sessions.deviceCodes["device-1"] = DeviceCode{
			DeviceCode: "device-1",
			UserCode:   "BCDF-GHJK",
			ClientID:   env.client.id,
			Status:     DeviceCodeStatusAuthorized,
			ExpiresAt:  env.now.Add(10 * time.Minute).Unix(),
		}

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

func TestGenerateUserCode(t *testing.T) {
	t.Parallel()

	pattern := regexp.MustCompile(
		`^[` + userCodeAlphabet + `]{4}-[` + userCodeAlphabet + `]{4}$`,
	)

	for range 100 {
		code, err := GenerateUserCode(t.Context())
		if err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}
		if !pattern.MatchString(code) {
			t.Fatalf("user code %q does not match %q", code, pattern)
		}
	}
}

func TestNormalizeUserCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want string
	}{
		{"BCDF-GHJK", "BCDF-GHJK"},
		{"bcdf-ghjk", "BCDF-GHJK"},
		{"bcdfghjk", "BCDF-GHJK"},
		{" bcdf ghjk ", "BCDF-GHJK"},
		{"bcd", "BCD"},
	}

	for _, tt := range tests {
		if got := normalizeUserCode(tt.in); got != tt.want {
			t.Errorf("normalizeUserCode(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}
}
