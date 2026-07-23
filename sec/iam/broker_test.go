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
	"github.com/deep-rent/nexus/sec/iam/idp"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// fakeIDP is a scriptable [idp.Provider].
type fakeIDP struct {
	identity idp.Claimant
	err      error
}

func (f *fakeIDP) AuthURL(_ context.Context, state string) (string, error) {
	return "https://idp.example.com/auth?state=" + url.QueryEscape(state), nil
}

func (f *fakeIDP) Exchange(
	_ context.Context,
	_ *http.Request,
) (idp.Claimant, error) {
	if f.err != nil {
		return idp.Claimant{}, f.err
	}
	return f.identity, nil
}

var _ idp.Provider = (*fakeIDP)(nil)

func postJSON(
	env *testEnv,
	path, body string,
	cookies ...*http.Cookie,
) *httptest.ResponseRecorder {
	req := httptest.NewRequest(
		http.MethodPost,
		testPrefix+path,
		strings.NewReader(body),
	)
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return env.do(req)
}

func sessionCookie(w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == DefaultSessionCookieName {
			return c
		}
	}
	return nil
}

func TestLogin(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)

		w := postJSON(
			env,
			PathLogin,
			`{"username":"alice","password":"wonderland"}`,
		)
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
		if !cookie.HttpOnly || !cookie.Secure {
			t.Error("session cookie should be HttpOnly and Secure")
		}
		if got, ok := sessionOwner(t, env.stores, cookie.Value); !ok {
			t.Error("session should have been persisted")
		} else if got != env.subject.id {
			t.Errorf("session maps to %v; want %v", got, env.subject.id)
		}
	})

	t.Run("invalid credentials", func(t *testing.T) {
		t.Parallel()
		env := newTestEnv(t)

		w := postJSON(
			env,
			PathLogin,
			`{"username":"alice","password":"nope"}`,
		)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusUnauthorized)
		}
		if env.stores.sessions.Len() != 0 {
			t.Error("no session should have been created")
		}
	})
}

func TestLogout(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	cookie := env.login()

	w := postJSON(env, PathLogout, "", cookie)
	if w.Code != http.StatusNoContent {
		t.Fatalf("got status %d; want %d", w.Code, http.StatusNoContent)
	}

	if _, ok := sessionOwner(t, env.stores, cookie.Value); ok {
		t.Error("session should have been deleted")
	}
	if got := w.Header().Get("Clear-Site-Data"); got != `"*"` {
		t.Errorf("got Clear-Site-Data %q; want %q", got, `"*"`)
	}
	if c := sessionCookie(w); c == nil || c.MaxAge >= 0 {
		t.Error("session cookie should have been cleared")
	}
}

func TestExternalFlow(t *testing.T) {
	t.Parallel()

	newEnv := func(t *testing.T, idp *fakeIDP) *testEnv {
		env := newTestEnv(t, WithIdentityProvider("acme", idp))
		env.subjects.external["acme/ext-123"] = env.subject.id
		return env
	}

	stateCookie := func(w *httptest.ResponseRecorder) *http.Cookie {
		for _, c := range w.Result().Cookies() {
			if c.Name == DefaultStateCookieName {
				return c
			}
		}
		return nil
	}

	login := func(t *testing.T, env *testEnv) (*http.Cookie, string) {
		t.Helper()
		w := env.do(httptest.NewRequest(
			http.MethodGet,
			testPrefix+"/login/acme",
			nil,
		))
		if w.Code != http.StatusFound {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusFound)
		}
		cookie := stateCookie(w)
		if cookie == nil || cookie.Value == "" {
			t.Fatal("missing state cookie")
		}
		loc, err := url.Parse(w.Header().Get("Location"))
		if err != nil {
			t.Fatalf("failed to parse redirect location: %v", err)
		}
		if got := loc.Query().Get("state"); got != cookie.Value {
			t.Fatalf("state %q does not match cookie %q", got, cookie.Value)
		}
		return cookie, cookie.Value
	}

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		env := newEnv(t, &fakeIDP{identity: idp.Claimant{Subject: "ext-123"}})

		cookie, state := login(t, env)

		req := httptest.NewRequest(
			http.MethodGet,
			testPrefix+"/callback/acme?state="+url.QueryEscape(state),
			nil,
		)
		req.AddCookie(cookie)

		w := env.do(req)
		if w.Code != http.StatusFound {
			t.Fatalf(
				"got status %d; want %d: %s",
				w.Code,
				http.StatusFound,
				w.Body,
			)
		}
		if got, want := w.Header().
			Get("Location"),
			"https://app.example.com/dashboard"; got != want {
			t.Errorf("got location %q; want %q", got, want)
		}

		session := sessionCookie(w)
		if session == nil || session.Value == "" {
			t.Fatal("missing session cookie")
		}
		if got, _ := sessionOwner(t, env.stores, session.Value); got != env.subject.id {
			t.Errorf("session maps to %v; want %v", got, env.subject.id)
		}
	})

	t.Run("form post callback", func(t *testing.T) {
		t.Parallel()
		env := newEnv(t, &fakeIDP{identity: idp.Claimant{Subject: "ext-123"}})

		cookie, state := login(t, env)

		// Sign in with Apple delivers the callback as a cross-site POST
		// carrying the state in the form body (response_mode=form_post).
		form := url.Values{"state": {state}, "code": {"abc"}}
		req := httptest.NewRequest(
			http.MethodPost,
			testPrefix+"/callback/acme",
			strings.NewReader(form.Encode()),
		)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)

		w := env.do(req)
		if w.Code != http.StatusFound {
			t.Fatalf(
				"got status %d; want %d: %s",
				w.Code,
				http.StatusFound,
				w.Body,
			)
		}
		if session := sessionCookie(w); session == nil || session.Value == "" {
			t.Fatal("missing session cookie")
		}
	})

	t.Run("state mismatch redirects to login terminal", func(t *testing.T) {
		t.Parallel()
		env := newEnv(t, &fakeIDP{identity: idp.Claimant{Subject: "ext-123"}})

		cookie, _ := login(t, env)

		req := httptest.NewRequest(
			http.MethodGet,
			testPrefix+"/callback/acme?state=tampered",
			nil,
		)
		req.AddCookie(cookie)

		w := env.do(req)

		// Errors must be delivered as an actual redirect: the user-agent
		// sits in a top-level navigation and cannot process a JSON body.
		if w.Code != http.StatusFound {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusFound)
		}
		loc, err := url.Parse(w.Header().Get("Location"))
		if err != nil {
			t.Fatalf("failed to parse redirect location: %v", err)
		}
		if !strings.HasPrefix(loc.String(), "https://app.example.com/login") {
			t.Fatalf("redirect %q should target the login terminal", loc)
		}
		if got := loc.Query().Get("error_status"); got != "400" {
			t.Errorf("got error_status %q; want %q", got, "400")
		}
	})

	t.Run("unlinked identity", func(t *testing.T) {
		t.Parallel()
		env := newEnv(t, &fakeIDP{identity: idp.Claimant{Subject: "stranger"}})

		cookie, state := login(t, env)

		req := httptest.NewRequest(
			http.MethodGet,
			testPrefix+"/callback/acme?state="+url.QueryEscape(state),
			nil,
		)
		req.AddCookie(cookie)

		w := env.do(req)
		if w.Code != http.StatusFound {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusFound)
		}
		loc, err := url.Parse(w.Header().Get("Location"))
		if err != nil {
			t.Fatalf("failed to parse redirect location: %v", err)
		}
		if got := loc.Query().Get("error_status"); got != "401" {
			t.Errorf("got error_status %q; want %q", got, "401")
		}
	})

	t.Run("unknown provider", func(t *testing.T) {
		t.Parallel()
		env := newEnv(t, &fakeIDP{})

		w := env.do(httptest.NewRequest(
			http.MethodGet,
			testPrefix+"/login/nonexistent",
			nil,
		))
		if w.Code != http.StatusNotFound {
			t.Fatalf("got status %d; want %d", w.Code, http.StatusNotFound)
		}
	})
}
