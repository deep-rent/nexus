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

package cors_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/deep-rent/nexus/net/middleware/cors"
	"github.com/deep-rent/nexus/std/ascii"
)

func TestNew_PanicsOnCredentialsWithoutOrigins(t *testing.T) {
	t.Parallel()

	t.Run("no origins", func(t *testing.T) {
		t.Parallel()
		defer func() {
			if recover() == nil {
				t.Error("should have panicked")
			}
		}()
		cors.New(cors.WithAllowCredentials(true))
	})

	t.Run("wildcard origin", func(t *testing.T) {
		t.Parallel()
		defer func() {
			if recover() == nil {
				t.Error("should have panicked")
			}
		}()
		cors.New(
			cors.WithAllowCredentials(true),
			cors.WithAllowedOrigins("*"),
		)
	})

	t.Run("explicit origins are fine", func(t *testing.T) {
		t.Parallel()
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("should not have panicked: %v", r)
			}
		}()
		cors.New(
			cors.WithAllowCredentials(true),
			cors.WithAllowedOrigins("http://a.com"),
		)
	})
}

func TestPreflightVary(t *testing.T) {
	t.Parallel()

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := cors.New()(next)

	r := httptest.NewRequest(http.MethodOptions, "/", nil)
	r.Header.Set("Origin", "http://a.com")
	r.Header.Set("Access-Control-Request-Method", http.MethodPut)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	want := []string{
		"Origin",
		"Access-Control-Request-Method",
		"Access-Control-Request-Headers",
	}
	got := w.Header().Values("Vary")
	if len(got) != len(want) {
		t.Fatalf("vary values: got %v; want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("vary at index %d: got %q; want %q", i, got[i], want[i])
		}
	}

	// Actual requests must only vary on Origin.
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Origin", "http://a.com")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if got := w.Header().Values("Vary"); len(got) != 1 || got[0] != "Origin" {
		t.Errorf("vary values for actual request: got %v; want [Origin]", got)
	}
}

func TestMiddleware(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		opts           []cors.Option
		reqMethod      string
		reqHeaders     map[string]string
		wantStatusCode int
		wantResHeaders map[string]string
		wantNextCalled bool
	}{
		{
			name: "non-cors request without origin header",
			opts: []cors.Option{
				cors.WithAllowedOrigins("http://a.com"),
			},
			reqMethod:      http.MethodGet,
			reqHeaders:     nil,
			wantStatusCode: http.StatusOK,
			wantResHeaders: nil,
			wantNextCalled: true,
		},
		{
			name: "explicit wildcard behaves like default",
			opts: []cors.Option{
				cors.WithAllowedOrigins("http://a.com", "*"),
			},
			reqMethod:      http.MethodGet,
			reqHeaders:     map[string]string{"Origin": "http://b.com"},
			wantStatusCode: http.StatusOK,
			wantResHeaders: map[string]string{
				"Access-Control-Allow-Origin": "*",
				"Vary":                        "Origin",
			},
			wantNextCalled: true,
		},
		{
			name:           "actual request with default settings",
			opts:           nil,
			reqMethod:      http.MethodGet,
			reqHeaders:     map[string]string{"Origin": "http://a.com"},
			wantStatusCode: http.StatusOK,
			wantResHeaders: map[string]string{
				"Access-Control-Allow-Origin": "*",
				"Vary":                        "Origin",
			},
			wantNextCalled: true,
		},
		{
			name:      "preflight request with default settings",
			opts:      nil,
			reqMethod: http.MethodOptions,
			reqHeaders: map[string]string{
				"Origin":                        "http://a.com",
				"Access-Control-Request-Method": http.MethodGet,
			},
			wantStatusCode: http.StatusNoContent,
			wantResHeaders: map[string]string{
				"Access-Control-Allow-Origin": "*",
				"Vary":                        "Origin",
			},
			wantNextCalled: false,
		},
		{
			name: "invalid preflight request without method passes through",
			opts: []cors.Option{
				cors.WithAllowedMethods(http.MethodPut),
			},
			reqMethod:      http.MethodOptions,
			reqHeaders:     map[string]string{"Origin": "http://a.com"},
			wantStatusCode: http.StatusOK,
			wantResHeaders: nil,
			wantNextCalled: true,
		},
		{
			name: "request with disallowed origin passes through",
			opts: []cors.Option{
				cors.WithAllowedOrigins("http://a.com"),
			},
			reqMethod:      http.MethodGet,
			reqHeaders:     map[string]string{"Origin": "http://b.com"},
			wantStatusCode: http.StatusOK,
			wantResHeaders: nil,
			wantNextCalled: true,
		},
		{
			name: "preflight request with full configuration",
			opts: []cors.Option{
				cors.WithAllowedOrigins("http://a.com"),
				cors.WithAllowedMethods(http.MethodPut, http.MethodPatch),
				cors.WithAllowedHeaders("X-Custom-Header"),
				cors.WithMaxAge(12 * time.Hour),
			},
			reqMethod: http.MethodOptions,
			reqHeaders: map[string]string{
				"Origin":                         "http://a.com",
				"Access-Control-Request-Method":  http.MethodPut,
				"Access-Control-Request-Headers": "X-Custom-Header",
			},
			wantStatusCode: http.StatusNoContent,
			wantResHeaders: map[string]string{
				"Access-Control-Allow-Origin":  "http://a.com",
				"Access-Control-Allow-Methods": "PUT, PATCH",
				"Access-Control-Allow-Headers": "X-Custom-Header",
				"Access-Control-Max-Age":       "43200",
				"Vary":                         "Origin",
			},
			wantNextCalled: false,
		},
		{
			name: "actual request with exposed headers",
			opts: []cors.Option{
				cors.WithAllowedOrigins("http://a.com"),
				cors.WithExposedHeaders("X-Pagination-Total"),
			},
			reqMethod:      http.MethodGet,
			reqHeaders:     map[string]string{"Origin": "http://a.com"},
			wantStatusCode: http.StatusOK,
			wantResHeaders: map[string]string{
				"Access-Control-Allow-Origin":   "http://a.com",
				"Access-Control-Expose-Headers": "X-Pagination-Total",
				"Vary":                          "Origin",
			},
			wantNextCalled: true,
		},
		{
			name: "actual request with credentials reflecting origin",
			opts: []cors.Option{
				cors.WithAllowCredentials(true),
				cors.WithAllowedOrigins("http://a.com", "http://b.com"),
			},
			reqMethod:      http.MethodGet,
			reqHeaders:     map[string]string{"Origin": "http://b.com"},
			wantStatusCode: http.StatusOK,
			wantResHeaders: map[string]string{
				"Access-Control-Allow-Origin":      "http://b.com",
				"Access-Control-Allow-Credentials": "true",
				"Vary":                             "Origin",
			},
			wantNextCalled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var called bool
			next := http.HandlerFunc(
				func(w http.ResponseWriter, _ *http.Request) {
					called = true
					w.WriteHeader(http.StatusOK)
				},
			)

			handler := cors.New(tt.opts...)(next)
			r := httptest.NewRequest(tt.reqMethod, "/", nil)
			for k, v := range tt.reqHeaders {
				r.Header.Set(k, v)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)

			if got, want := w.Code, tt.wantStatusCode; got != want {
				t.Errorf("status code: got %d; want %d", got, want)
			}

			if got, want := called, tt.wantNextCalled; got != want {
				t.Errorf("next called: got %v; want %v", got, want)
			}

			if tt.wantResHeaders == nil {
				for h := range w.Header() {
					if strings.Contains(ascii.ToLower(h), "access-control-") {
						t.Errorf("unexpected cors header: %s", h)
					}
				}
			} else {
				for k, want := range tt.wantResHeaders {
					if got := w.Header().Get(k); got != want {
						t.Errorf("for header %q: got %q; want %q", k, got, want)
					}
				}
			}
		})
	}
}
