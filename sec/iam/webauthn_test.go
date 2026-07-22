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
	"encoding/json/jsontext"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"uuid"

	"github.com/deep-rent/nexus/sec/auth"
	"github.com/deep-rent/nexus/sec/iam/oauth"
	"github.com/deep-rent/nexus/sec/jose/jwt"
)

const (
	testRPID     = "example.com"
	testRPName   = "Example"
	testRPOrigin = "https://app.example.com"
)

// webAuthnEnv bundles a passkey-enabled [testEnv] with a virtual
// authenticator that produces real, verifiable attestations and assertions.
type webAuthnEnv struct {
	*testEnv
	rp            virtualwebauthn.RelyingParty
	authenticator virtualwebauthn.Authenticator
	cred          virtualwebauthn.Credential
}

func newWebAuthnEnv(t *testing.T, opts ...Option) *webAuthnEnv {
	t.Helper()

	opts = append([]Option{
		WithWebAuthn(WebAuthnConfig{
			RPID:          testRPID,
			RPDisplayName: testRPName,
			RPOrigins:     []string{testRPOrigin},
		}),
	}, opts...)

	env := &webAuthnEnv{
		testEnv: newTestEnv(t, opts...),
		rp: virtualwebauthn.RelyingParty{
			ID:     testRPID,
			Name:   testRPName,
			Origin: testRPOrigin,
		},
		cred: virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2),
	}

	// The user handle stored on the virtual authenticator is what the
	// server resolves the account from during discoverable logins.
	env.authenticator = virtualwebauthn.NewAuthenticatorWithOptions(
		virtualwebauthn.AuthenticatorOptions{
			UserHandle: env.subject.id[:],
		},
	)

	// Allow the default clients to use the WebAuthn grant.
	env.client.grants = append(env.client.grants, oauth.GrantTypeWebAuthn)
	env.public.grants = append(env.public.grants, oauth.GrantTypeWebAuthn)

	return env
}

// optionsEnvelope mirrors [WebAuthnOptionsResponse] with the options kept
// raw, so they can be handed to the virtual authenticator verbatim.
type optionsEnvelope struct {
	Handle    string         `json:"handle"`
	ExpiresIn int64          `json:"expires_in"`
	Options   jsontext.Value `json:"options"`
}

// beginRegistration requests registration options with the given
// authentication cookie and parses them for the virtual authenticator.
func (env *webAuthnEnv) beginRegistration(
	t *testing.T,
	cookie *http.Cookie,
) (string, *virtualwebauthn.AttestationOptions) {
	t.Helper()

	w := postJSON(env.testEnv, PathWebAuthnRegisterOptions, "", cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("got status %d; want %d: %s", w.Code, http.StatusOK, w.Body)
	}

	res := decodeJSON[optionsEnvelope](t, w)
	opts, err := virtualwebauthn.ParseAttestationOptions(string(res.Options))
	if err != nil {
		t.Fatalf("failed to parse attestation options: %v", err)
	}
	return res.Handle, opts
}

// register performs a complete registration ceremony for the default
// subject and arms the virtual authenticator with the new credential.
func (env *webAuthnEnv) register(t *testing.T) {
	t.Helper()

	cookie := env.login()
	handle, opts := env.beginRegistration(t, cookie)

	attestation := virtualwebauthn.CreateAttestationResponse(
		env.rp,
		env.authenticator,
		env.cred,
		*opts,
	)

	w := postJSON(
		env.testEnv,
		PathWebAuthnRegister,
		fmt.Sprintf(
			`{"handle":%q,"name":"test key","credential":%s}`,
			handle,
			attestation,
		),
		cookie,
	)
	if w.Code != http.StatusNoContent {
		t.Fatalf(
			"got status %d; want %d: %s",
			w.Code,
			http.StatusNoContent,
			w.Body,
		)
	}

	env.authenticator.AddCredential(env.cred)
}

// beginLogin requests login options and parses them for the virtual
// authenticator.
func (env *webAuthnEnv) beginLogin(
	t *testing.T,
) (string, *virtualwebauthn.AssertionOptions) {
	t.Helper()

	w := postJSON(env.testEnv, PathWebAuthnLoginOptions, "")
	if w.Code != http.StatusOK {
		t.Fatalf("got status %d; want %d: %s", w.Code, http.StatusOK, w.Body)
	}

	res := decodeJSON[optionsEnvelope](t, w)
	opts, err := virtualwebauthn.ParseAssertionOptions(string(res.Options))
	if err != nil {
		t.Fatalf("failed to parse assertion options: %v", err)
	}
	return res.Handle, opts
}

// assert produces a signed assertion response for the given options.
func (env *webAuthnEnv) assert(
	opts *virtualwebauthn.AssertionOptions,
) string {
	return virtualwebauthn.CreateAssertionResponse(
		env.rp,
		env.authenticator,
		env.cred,
		*opts,
	)
}

// mintToken signs a first-party access token for the default subject, as
// issued to the default client via a delegated grant.
func (env *webAuthnEnv) mintToken(t *testing.T) string {
	t.Helper()

	now := env.now
	claims := &auth.Claims{
		Azp: env.client.id.String(),
		Sub: env.subject.id.String(),
		Jti: uuid.New().String(),
		Iss: testIssuer,
		Iat: now,
		Nbf: now,
		Exp: now.Add(time.Hour),
	}

	token, err := jwt.Sign(t.Context(), env.vault.Next(), claims)
	if err != nil {
		t.Fatalf("failed to mint access token: %v", err)
	}
	return string(token)
}

func TestWebAuthnRegistration(t *testing.T) {
	t.Parallel()

	t.Run("registers a passkey via session cookie", func(t *testing.T) {
		t.Parallel()
		env := newWebAuthnEnv(t)
		cookie := env.login()

		handle, opts := env.beginRegistration(t, cookie)
		if handle == "" {
			t.Fatal("missing handle")
		}
		if opts.RelyingPartyID != testRPID {
			t.Errorf("got RP ID %q; want %q", opts.RelyingPartyID, testRPID)
		}
		if opts.UserID != string(env.subject.id[:]) {
			t.Error("options should carry the subject UUID as user handle")
		}
		if opts.UserName != "alice" {
			t.Errorf("got user name %q; want %q", opts.UserName, "alice")
		}

		attestation := virtualwebauthn.CreateAttestationResponse(
			env.rp,
			env.authenticator,
			env.cred,
			*opts,
		)

		w := postJSON(
			env.testEnv,
			PathWebAuthnRegister,
			fmt.Sprintf(
				`{"handle":%q,"name":"test key","credential":%s}`,
				handle,
				attestation,
			),
			cookie,
		)
		if w.Code != http.StatusNoContent {
			t.Fatalf(
				"got status %d; want %d: %s",
				w.Code,
				http.StatusNoContent,
				w.Body,
			)
		}

		creds := env.subjects.credentials[env.subject.id]
		if len(creds) != 1 {
			t.Fatalf("got %d stored credentials; want 1", len(creds))
		}
		if !slices.Equal(creds[0].ID, env.cred.ID) {
			t.Error("stored credential ID does not match the authenticator")
		}
		if env.stores.ceremonies.Len() != 0 {
			t.Error("ceremony session should have been deleted")
		}
	})

	t.Run("registers a passkey via bearer token", func(t *testing.T) {
		t.Parallel()
		env := newWebAuthnEnv(t)
		token := env.mintToken(t)

		req := httptest.NewRequest(
			http.MethodPost,
			testPrefix+PathWebAuthnRegisterOptions,
			strings.NewReader(""),
		)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		w := env.do(req)
		if w.Code != http.StatusOK {
			t.Fatalf(
				"got status %d; want %d: %s",
				w.Code,
				http.StatusOK,
				w.Body,
			)
		}

		res := decodeJSON[optionsEnvelope](t, w)
		if res.Handle == "" {
			t.Fatal("missing handle")
		}
	})

	t.Run("requires authentication", func(t *testing.T) {
		t.Parallel()
		env := newWebAuthnEnv(t)

		w := postJSON(env.testEnv, PathWebAuthnRegisterOptions, "")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusUnauthorized)
		}
	})

	t.Run("excludes registered credentials", func(t *testing.T) {
		t.Parallel()
		env := newWebAuthnEnv(t)
		env.register(t)

		_, opts := env.beginRegistration(t, env.login())
		if !env.cred.IsExcludedForAttestation(*opts) {
			t.Error("registered credential should be excluded")
		}
	})

	t.Run("rejects a mismatched challenge", func(t *testing.T) {
		t.Parallel()
		env := newWebAuthnEnv(t)
		cookie := env.login()

		// The attestation answers the challenge of the first ceremony but
		// is submitted for the second one.
		_, stale := env.beginRegistration(t, cookie)
		handle, _ := env.beginRegistration(t, cookie)

		attestation := virtualwebauthn.CreateAttestationResponse(
			env.rp,
			env.authenticator,
			env.cred,
			*stale,
		)

		w := postJSON(
			env.testEnv,
			PathWebAuthnRegister,
			fmt.Sprintf(`{"handle":%q,"credential":%s}`, handle, attestation),
			cookie,
		)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusBadRequest)
		}
		if len(env.subjects.credentials[env.subject.id]) != 0 {
			t.Error("no credential should have been stored")
		}
	})

	t.Run("rejects an unknown handle", func(t *testing.T) {
		t.Parallel()
		env := newWebAuthnEnv(t)
		cookie := env.login()

		w := postJSON(
			env.testEnv,
			PathWebAuthnRegister,
			`{"handle":"no-such-handle","credential":{}}`,
			cookie,
		)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusUnauthorized)
		}
	})

	t.Run("handles are single use", func(t *testing.T) {
		t.Parallel()
		env := newWebAuthnEnv(t)
		cookie := env.login()

		handle, opts := env.beginRegistration(t, cookie)
		attestation := virtualwebauthn.CreateAttestationResponse(
			env.rp,
			env.authenticator,
			env.cred,
			*opts,
		)
		body := fmt.Sprintf(
			`{"handle":%q,"credential":%s}`,
			handle,
			attestation,
		)

		if w := postJSON(
			env.testEnv,
			PathWebAuthnRegister,
			body,
			cookie,
		); w.Code != http.StatusNoContent {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusNoContent)
		}
		if w := postJSON(
			env.testEnv,
			PathWebAuthnRegister,
			body,
			cookie,
		); w.Code != http.StatusUnauthorized {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusUnauthorized)
		}
	})

	t.Run("endpoints are absent without WebAuthn", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)

		for _, path := range []string{
			PathWebAuthnRegisterOptions,
			PathWebAuthnRegister,
			PathWebAuthnLoginOptions,
			PathWebAuthnLogin,
		} {
			w := postJSON(env, path, "{}")
			if w.Code != http.StatusNotFound {
				t.Errorf(
					"%s: got status %d; want %d",
					path,
					w.Code,
					http.StatusNotFound,
				)
			}
		}
	})
}

func TestWebAuthnLogin(t *testing.T) {
	t.Parallel()

	finish := func(
		env *webAuthnEnv,
		handle, assertion string,
	) *httptest.ResponseRecorder {
		return postJSON(
			env.testEnv,
			PathWebAuthnLogin,
			fmt.Sprintf(`{"handle":%q,"credential":%s}`, handle, assertion),
		)
	}

	t.Run("establishes a session", func(t *testing.T) {
		t.Parallel()
		env := newWebAuthnEnv(t)
		env.register(t)
		env.cred.Counter = 7

		handle, opts := env.beginLogin(t)
		w := finish(env, handle, env.assert(opts))
		if w.Code != http.StatusNoContent {
			t.Fatalf(
				"got status %d; want %d: %s",
				w.Code,
				http.StatusNoContent,
				w.Body,
			)
		}

		cookie := sessionCookie(w)
		if cookie == nil || cookie.Value == "" {
			t.Fatal("missing session cookie")
		}
		if got := env.subjects.sessions[cookie.Value]; got != env.subject.id {
			t.Errorf("session maps to %v; want %v", got, env.subject.id)
		}

		// The updated signature counter must have been persisted.
		creds := env.subjects.credentials[env.subject.id]
		if len(creds) != 1 || creds[0].Authenticator.SignCount != 7 {
			t.Errorf("stored sign count was not updated: %+v", creds)
		}
	})

	t.Run("rejects an unknown handle", func(t *testing.T) {
		t.Parallel()
		env := newWebAuthnEnv(t)
		env.register(t)

		_, opts := env.beginLogin(t)
		w := finish(env, "no-such-handle", env.assert(opts))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusUnauthorized)
		}
	})

	t.Run("rejects an expired handle", func(t *testing.T) {
		t.Parallel()
		env := newWebAuthnEnv(t)
		env.register(t)

		handle, opts := env.beginLogin(t)
		env.now = env.now.Add(DefaultWebAuthnSessionLifetime + time.Second)

		w := finish(env, handle, env.assert(opts))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusUnauthorized)
		}
	})

	t.Run("rejects a registration handle", func(t *testing.T) {
		t.Parallel()
		env := newWebAuthnEnv(t)
		env.register(t)

		// A handle minted for a registration ceremony must not finish a
		// login ceremony.
		regHandle, _ := env.beginRegistration(t, env.login())
		_, opts := env.beginLogin(t)

		w := finish(env, regHandle, env.assert(opts))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusUnauthorized)
		}
	})

	t.Run("rejects an unregistered credential", func(t *testing.T) {
		t.Parallel()
		env := newWebAuthnEnv(t)
		env.register(t)

		// A fresh credential with a valid user handle but unknown key.
		env.cred = virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

		handle, opts := env.beginLogin(t)
		w := finish(env, handle, env.assert(opts))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusUnauthorized)
		}
		if sessionCookie(w) != nil {
			t.Error("no session cookie should have been set")
		}
	})

	t.Run("rejects an unknown user handle", func(t *testing.T) {
		t.Parallel()
		env := newWebAuthnEnv(t)
		env.register(t)

		other := uuid.New()
		env.authenticator.Options.UserHandle = other[:]

		handle, opts := env.beginLogin(t)
		w := finish(env, handle, env.assert(opts))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusUnauthorized)
		}
	})

	t.Run("detects a cloned authenticator", func(t *testing.T) {
		t.Parallel()
		env := newWebAuthnEnv(t)
		env.register(t)

		// First login records sign count 7.
		env.cred.Counter = 7
		handle, opts := env.beginLogin(t)
		if w := finish(
			env,
			handle,
			env.assert(opts),
		); w.Code != http.StatusNoContent {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusNoContent)
		}

		// A second assertion with a non-increasing counter indicates a
		// cloned key and must be refused.
		handle, opts = env.beginLogin(t)
		if w := finish(
			env,
			handle,
			env.assert(opts),
		); w.Code != http.StatusUnauthorized {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusUnauthorized)
		}
	})
}

func TestWebAuthnGrant(t *testing.T) {
	t.Parallel()

	t.Run("exchanges an assertion for tokens", func(t *testing.T) {
		t.Parallel()
		env := newWebAuthnEnv(t)
		env.register(t)
		env.cred.Counter = 3

		handle, opts := env.beginLogin(t)

		w := env.postForm(PathToken, url.Values{
			"grant_type": {string(oauth.GrantTypeWebAuthn)},
			"handle":     {handle},
			"assertion":  {env.assert(opts)},
			"scope":      {"read"},
		}, env.client, "s3cret")
		if w.Code != http.StatusOK {
			t.Fatalf(
				"got status %d; want %d: %s",
				w.Code,
				http.StatusOK,
				w.Body,
			)
		}

		res := decodeJSON[oauth.TokenResponse](t, w)
		claims := env.verifyToken(t, res.AccessToken)
		if claims.Sub != env.subject.id.String() {
			t.Errorf("got sub %q; want %q", claims.Sub, env.subject.id)
		}
		if got := claims.Scope.String(); got != "read" {
			t.Errorf("got scope %q; want %q", got, "read")
		}
		if res.RefreshToken == "" {
			t.Error("missing refresh token")
		}
	})

	t.Run("validates the request", func(t *testing.T) {
		t.Parallel()
		env := newWebAuthnEnv(t)
		env.register(t)

		handle, opts := env.beginLogin(t)
		assertion := env.assert(opts)

		tests := []struct {
			name string
			form url.Values
			code string
		}{
			{
				name: "missing handle",
				form: url.Values{
					"assertion": {assertion},
				},
				code: oauth.ErrorCodeInvalidRequest,
			},
			{
				name: "missing assertion",
				form: url.Values{
					"handle": {handle},
				},
				code: oauth.ErrorCodeInvalidRequest,
			},
			{
				name: "disallowed scope",
				form: url.Values{
					"handle":    {handle},
					"assertion": {assertion},
					"scope":     {"admin"},
				},
				code: oauth.ErrorCodeInvalidScope,
			},
			{
				name: "unknown handle",
				form: url.Values{
					"handle":    {"no-such-handle"},
					"assertion": {assertion},
				},
				code: oauth.ErrorCodeInvalidGrant,
			},
			{
				name: "malformed assertion",
				form: url.Values{
					"handle":    {handle},
					"assertion": {"not json"},
				},
				code: oauth.ErrorCodeInvalidGrant,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				tt.form.Set("grant_type", string(oauth.GrantTypeWebAuthn))
				w := env.postForm(PathToken, tt.form, env.client, "s3cret")
				res := decodeJSON[oauth.Error](t, w)
				if res.Code != tt.code {
					t.Errorf(
						"got code %q; want %q: %s",
						res.Code,
						tt.code,
						w.Body,
					)
				}
			})
		}
	})

	t.Run("requires grant permission", func(t *testing.T) {
		t.Parallel()
		env := newWebAuthnEnv(t)
		env.register(t)
		env.client.grants = slices.DeleteFunc(
			slices.Clone(env.client.grants),
			func(g oauth.GrantType) bool { return g == oauth.GrantTypeWebAuthn },
		)

		handle, opts := env.beginLogin(t)

		w := env.postForm(PathToken, url.Values{
			"grant_type": {string(oauth.GrantTypeWebAuthn)},
			"handle":     {handle},
			"assertion":  {env.assert(opts)},
		}, env.client, "s3cret")

		res := decodeJSON[oauth.Error](t, w)
		if res.Code != oauth.ErrorCodeUnauthorizedClient {
			t.Errorf(
				"got code %q; want %q",
				res.Code,
				oauth.ErrorCodeUnauthorizedClient,
			)
		}
	})

	t.Run("announces the grant in the metadata", func(t *testing.T) {
		t.Parallel()
		env := newWebAuthnEnv(t)

		w := env.do(httptest.NewRequest(
			http.MethodGet,
			testPrefix+PathWellKnown,
			nil,
		))
		if w.Code != http.StatusOK {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusOK)
		}

		meta := decodeJSON[oauth.ServerMetadata](t, w)
		if !slices.Contains(
			meta.GrantTypesSupported,
			string(oauth.GrantTypeWebAuthn),
		) {
			t.Errorf(
				"metadata does not announce %q: %v",
				oauth.GrantTypeWebAuthn,
				meta.GrantTypesSupported,
			)
		}
	})
}
