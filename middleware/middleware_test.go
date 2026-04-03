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

package middleware_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mw "github.com/deep-rent/nexus/middleware"
)

var mockHandler = http.HandlerFunc(
	func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	},
)

func mockLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}

func TestChain(t *testing.T) {
	t.Parallel()

	t.Run("chains pipes in correct order", func(t *testing.T) {
		t.Parallel()
		var order []string
		rec := func(id string) mw.Pipe {
			return func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					order = append(order, id)
					next.ServeHTTP(w, r)
				})
			}
		}

		h := mw.Chain(mockHandler, rec("a"), rec("b"), rec("c"))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))

		want := "a,b,c"
		if got := strings.Join(order, ","); got != want {
			t.Errorf("Chain() order = %q; want %q", got, want)
		}
	})

	t.Run("ignores nil pipes", func(t *testing.T) {
		t.Parallel()
		var called bool
		p := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				next.ServeHTTP(w, r)
			})
		}

		h := mw.Chain(mockHandler, nil, p, nil)
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))

		if !called {
			t.Errorf("Chain() = %v; want true", called)
		}
	})

	t.Run("returns original handler if no pipes", func(t *testing.T) {
		t.Parallel()
		h := mw.Chain(mockHandler)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

		if got, want := rr.Code, http.StatusOK; got != want {
			t.Errorf("Chain().Code = %d; want %d", got, want)
		}
		if got, want := rr.Body.String(), "ok"; got != want {
			t.Errorf("Chain().Body = %q; want %q", got, want)
		}
	})
}

func TestRecover(t *testing.T) {
	t.Parallel()

	t.Run("recovers from panic", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		logger := mockLogger(&buf)
		pipe := mw.Recover(logger)

		h := pipe(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic("test")
		}))
		req := httptest.NewRequest("GET", "/panic", nil)
		rr := httptest.NewRecorder()

		h.ServeHTTP(rr, req)

		if got, want := rr.Code, http.StatusInternalServerError; got != want {
			t.Errorf("Recover().Code = %d; want %d", got, want)
		}

		out := buf.String()
		contains := []string{
			"Panic caught by middleware",
			"panic=test",
			"url=/panic",
			"stack=",
		}
		for _, want := range contains {
			if !strings.Contains(out, want) {
				t.Errorf("Recover() log missing %q; got %q", want, out)
			}
		}
	})

	t.Run("does nothing if no panic", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		logger := mockLogger(&buf)
		pipe := mw.Recover(logger)

		h := pipe(mockHandler)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", "/ok", nil))

		if got, want := rr.Code, http.StatusOK; got != want {
			t.Errorf("Recover().Code = %d; want %d", got, want)
		}
		if got, want := rr.Body.String(), "ok"; got != want {
			t.Errorf("Recover().Body = %q; want %q", got, want)
		}
		if got := buf.String(); len(got) != 0 {
			t.Errorf("Recover() log = %q; want empty", got)
		}
	})
}

func TestRequestID(t *testing.T) {
	t.Parallel()
	var captured string
	trap := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = mw.GetRequestID(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	h := mw.RequestID()(trap)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	id := rr.Header().Get("X-Request-ID")
	if len(id) == 0 {
		t.Fatalf("RequestID() X-Request-ID header is empty")
	}
	if got, want := len(id), 32; got != want {
		t.Errorf("len(RequestID()) = %d; want %d", got, want)
	}
	if len(captured) == 0 {
		t.Fatalf("RequestID() captured context ID is empty")
	}
	if id != captured {
		t.Errorf("RequestID() = %q; want %q", id, captured)
	}
}

func TestGetSetRequestID(t *testing.T) {
	t.Parallel()

	t.Run("get from empty context", func(t *testing.T) {
		t.Parallel()
		if got := mw.GetRequestID(t.Context()); len(got) != 0 {
			t.Errorf("GetRequestID() = %q; want empty", got)
		}
	})

	t.Run("set and get id", func(t *testing.T) {
		t.Parallel()
		want := "test-id"
		ctx := mw.SetRequestID(t.Context(), want)
		if got := mw.GetRequestID(ctx); got != want {
			t.Errorf("GetRequestID() = %q; want %q", got, want)
		}
	})
}

func TestLog(t *testing.T) {
	t.Parallel()

	t.Run("logs with non-default status", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		logger := mockLogger(&buf)
		pipe := mw.Log(logger)

		final := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})

		h := pipe(final)
		req := httptest.NewRequest("POST", "/path?q=1", nil)
		req.RemoteAddr = "1.2.3.4:12345"
		req.Header.Set("User-Agent", "test-agent")
		req = req.WithContext(mw.SetRequestID(req.Context(), "test-id"))

		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if got, want := rr.Code, http.StatusNotFound; got != want {
			t.Errorf("Log().Code = %d; want %d", got, want)
		}

		out := buf.String()
		contains := []string{
			`level=DEBUG msg="HTTP request handled"`,
			`id=test-id`,
			`method=POST`,
			`url="/path?q=1"`,
			`remote=1.2.3.4:12345`,
			`agent=test-agent`,
			`status=404`,
			`duration=`,
		}
		for _, want := range contains {
			if !strings.Contains(out, want) {
				t.Errorf("Log() log missing %q; got %q", want, out)
			}
		}
	})

	t.Run("logs with default status", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		logger := mockLogger(&buf)
		pipe := mw.Log(logger)

		final := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("ok"))
		})

		ch := pipe(final)
		rr := httptest.NewRecorder()
		ch.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

		if got, want := rr.Code, http.StatusOK; got != want {
			t.Errorf("Log().Code = %d; want %d", got, want)
		}
		if want := `status=200`; !strings.Contains(buf.String(), want) {
			t.Errorf("Log() log missing %q", want)
		}
	})
}

func TestVolatile(t *testing.T) {
	t.Parallel()
	h := mw.Volatile()(mockHandler)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	wantCC := "no-store, no-cache, must-revalidate, proxy-revalidate"

	if got, want := rr.Code, http.StatusOK; got != want {
		t.Errorf("Volatile().Code = %d; want %d", got, want)
	}
	if got := rr.Header().Get("Cache-Control"); got != wantCC {
		t.Errorf("Volatile() Cache-Control = %q; want %q", got, wantCC)
	}
	if got, want := rr.Header().Get("Pragma"), "no-cache"; got != want {
		t.Errorf("Volatile() Pragma = %q; want %q", got, want)
	}
	if got, want := rr.Header().Get("Expires"), "0"; got != want {
		t.Errorf("Volatile() Expires = %q; want %q", got, want)
	}
}

func TestSecure(t *testing.T) {
	t.Parallel()

	t.Run("uses default config", func(t *testing.T) {
		t.Parallel()
		h := mw.Secure(mw.DefaultSecurityConfig)(mockHandler)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

		if got, want := rr.Code, http.StatusOK; got != want {
			t.Errorf("Secure().Code = %d; want %d", got, want)
		}

		hsts := rr.Header().Get("Strict-Transport-Security")
		if !strings.Contains(hsts, "max-age=31536000") {
			t.Errorf("HSTS max-age missing; got %q", hsts)
		}
		if !strings.Contains(hsts, "includeSubDomains") {
			t.Errorf("HSTS includeSubDomains missing; got %q", hsts)
		}

		tests := []struct {
			key  string
			want string
		}{
			{
				"X-Content-Type-Options",
				"nosniff",
			},
			{
				"X-Frame-Options",
				"DENY",
			},
			{
				"Permissions-Policy",
				"geolocation=(),microphone=(),camera=(),payment=()",
			},
			{
				"Cross-Origin-Opener-Policy",
				"same-origin",
			},
			{
				"X-Permitted-Cross-Domain-Policies",
				"none",
			},
		}

		for _, tt := range tests {
			if got := rr.Header().Get(tt.key); got != tt.want {
				t.Errorf("Secure() %s = %q; want %q", tt.key, got, tt.want)
			}
		}
	})

	t.Run("applies custom config", func(t *testing.T) {
		t.Parallel()
		cfg := mw.SecurityConfig{
			STSMaxAge:               60,
			STSIncludeSubdomains:    false,
			FrameOptions:            "SAMEORIGIN",
			NoSniff:                 true,
			CSP:                     "default-src 'self'",
			ReferrerPolicy:          "no-referrer",
			PermissionsPolicy:       "geolocation=()",
			CrossOriginOpenerPolicy: "same-origin-allow-popups",
		}
		h := mw.Secure(cfg)(mockHandler)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

		hdr := rr.Header()
		tests := []struct {
			key  string
			want string
		}{
			{"Strict-Transport-Security", "max-age=60"},
			{"X-Frame-Options", "SAMEORIGIN"},
			{"X-Content-Type-Options", "nosniff"},
			{"Content-Security-Policy", "default-src 'self'"},
			{"Referrer-Policy", "no-referrer"},
			{"Permissions-Policy", "geolocation=()"},
			{"Cross-Origin-Opener-Policy", "same-origin-allow-popups"},
			{"X-Permitted-Cross-Domain-Policies", "none"},
		}

		for _, tt := range tests {
			if got := hdr.Get(tt.key); got != tt.want {
				t.Errorf("Secure() %s = %q; want %q", tt.key, got, tt.want)
			}
		}
	})

	t.Run("sets only hardcoded headers on empty config", func(t *testing.T) {
		t.Parallel()
		cfg := mw.SecurityConfig{}
		h := mw.Secure(cfg)(mockHandler)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

		hdr := rr.Header()
		checks := []string{
			"Strict-Transport-Security",
			"X-Frame-Options",
			"X-Content-Type-Options",
			"Content-Security-Policy",
			"Referrer-Policy",
			"Permissions-Policy",
			"Cross-Origin-Opener-Policy",
		}

		for _, k := range checks {
			if got := hdr.Get(k); len(got) != 0 {
				t.Errorf("Secure() %s = %q; want empty", k, got)
			}
		}

		const key = "X-Permitted-Cross-Domain-Policies"
		if got, want := hdr.Get(key), "none"; got != want {
			t.Errorf("Secure() %s = %q; want %q", key, got, want)
		}
	})
}

func TestIntegration(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := mockLogger(&buf)

	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := mw.GetRequestID(r.Context()); len(id) == 0 {
			t.Errorf("GetRequestID() = %q; want non-empty", id)
		}
		w.WriteHeader(http.StatusAccepted)
	})

	h := mw.Chain(
		final,
		mw.Recover(logger),
		mw.RequestID(),
		mw.Log(logger),
		mw.Secure(mw.DefaultSecurityConfig),
		mw.Volatile(),
	)

	req := httptest.NewRequest("GET", "/int", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	id := rr.Header().Get("X-Request-ID")
	if len(id) == 0 {
		t.Fatalf("Integration X-Request-ID header is empty")
	}
	if got, want := rr.Code, http.StatusAccepted; got != want {
		t.Errorf("Integration.Code = %d; want %d", got, want)
	}

	tests := []struct {
		key  string
		want string
	}{
		{"X-Frame-Options", "DENY"},
		{"Cross-Origin-Opener-Policy", "same-origin"},
		{"Pragma", "no-cache"},
	}

	for _, tt := range tests {
		if got := rr.Header().Get(tt.key); got != tt.want {
			t.Errorf("Integration %s = %q; want %q", tt.key, got, tt.want)
		}
	}

	out := buf.String()
	contains := []string{
		"level=DEBUG",
		"id=" + id,
		"status=202",
	}
	for _, want := range contains {
		if !strings.Contains(out, want) {
			t.Errorf("Integration log missing %q; got %q", want, out)
		}
	}
}
