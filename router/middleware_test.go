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

package router_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/time/rate"

	"github.com/deep-rent/nexus/log"
	"github.com/deep-rent/nexus/middleware"
	"github.com/deep-rent/nexus/router"
)

func TestHandler_ChainMiddleware(t *testing.T) {
	t.Parallel()

	appendHeader := func(val string) router.Middleware {
		return func(next router.Handler) router.Handler {
			return router.HandlerFunc(func(e *router.Exchange) error {
				current := e.W.Header().Get("X-Chain")
				e.SetHeader("X-Chain", current+val)
				return next.ServeHTTP(e)
			})
		}
	}

	h := router.Chain(
		router.HandlerFunc(func(e *router.Exchange) error {
			current := e.W.Header().Get("X-Chain")
			e.SetHeader("X-Chain", current+"C")
			return nil
		}),
		appendHeader("A"),
		appendHeader("B"),
	)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	e := &router.Exchange{R: req, W: router.NewResponseWriter(rec)}

	if err := h.ServeHTTP(e); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if got, want := rec.Header().Get("X-Chain"), "ABC"; got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestHandler_WrapStd(t *testing.T) {
	t.Parallel()

	stdHandler := http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Wrapped", "true")
			w.WriteHeader(http.StatusAccepted)
		},
	)

	r := router.New()
	r.Handle("GET /wrap", router.Wrap(stdHandler))

	srv := httptest.NewServer(r)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/wrap")
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if got, want := res.StatusCode, http.StatusAccepted; got != want {
		t.Errorf("status code: got %d; want %d", got, want)
	}
	if got, want := res.Header.Get("X-Wrapped"), "true"; got != want {
		t.Errorf("header \"X-Wrapped\": got %q; want %q", got, want)
	}
}

func TestHandler_AdaptStdMiddleware(t *testing.T) {
	t.Parallel()

	var capturedStatus int
	pipe := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
			if rw, ok := w.(router.ResponseWriter); ok {
				capturedStatus = rw.Status()
			}
		})
	}

	r := router.New(router.WithMiddleware(router.Adapt(pipe)))
	r.HandleFunc("GET /adapt", func(e *router.Exchange) error {
		return errors.New("boom")
	})

	srv := httptest.NewServer(r)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/adapt")
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if got, want := res.StatusCode,
		http.StatusInternalServerError; got != want {
		t.Errorf("response status: got %d; want %d", got, want)
	}
	if got, want := capturedStatus,
		http.StatusInternalServerError; got != want {
		t.Errorf("captured status: got %d; want %d", got, want)
	}
}

func TestMiddleware_Connectivity(t *testing.T) {
	t.Parallel()

	logger := log.Silent()
	tests := []struct {
		name string
		fn   any
	}{
		{"Recover", router.Recover(logger)},
		{"RequestID", router.RequestID()},
		{"Log", router.Log(logger)},
		{"Volatile", router.Volatile()},
		{"Secure", router.Secure(middleware.DefaultSecurityConfig)},
		{"CORS", router.CORS()},
		{"Gzip", router.Gzip()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.fn == nil {
				t.Fatal("factory: got nil; want non-nil")
			}
			if _, ok := tt.fn.(router.Middleware); !ok {
				t.Error("should satisfy router.Middleware")
			}
		})
	}
}

func TestRateLimitFunc(t *testing.T) {
	t.Parallel()

	mockHandler := router.HandlerFunc(func(e *router.Exchange) error {
		e.Status(http.StatusOK)
		return nil
	})

	t.Run("allows when nil limiter", func(t *testing.T) {
		t.Parallel()
		h := router.RateLimitFunc(func(*http.Request) *rate.Limiter {
			return nil
		})(mockHandler)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		e := &router.Exchange{R: req, W: router.NewResponseWriter(rec)}

		if err := h.ServeHTTP(e); err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}
	})

	t.Run("limits when limiter supplied", func(t *testing.T) {
		t.Parallel()
		limiter := rate.NewLimiter(0, 1)
		h := router.RateLimitFunc(func(*http.Request) *rate.Limiter {
			return limiter
		})(mockHandler)

		rec1 := httptest.NewRecorder()
		e1 := &router.Exchange{
			R: httptest.NewRequest(http.MethodGet, "/", nil),
			W: router.NewResponseWriter(rec1),
		}
		if err := h.ServeHTTP(e1); err != nil {
			t.Fatalf("first request should succeed: %v", err)
		}

		rec2 := httptest.NewRecorder()
		e2 := &router.Exchange{
			R: httptest.NewRequest(http.MethodGet, "/", nil),
			W: router.NewResponseWriter(rec2),
		}
		err := h.ServeHTTP(e2)
		if err == nil {
			t.Fatal("second request should fail")
		}

		var re *router.Error
		if !errors.As(err, &re) {
			t.Fatalf("error type: got %T; want *router.Error", err)
		}
		if got, want := re.Status, http.StatusTooManyRequests; got != want {
			t.Errorf("status code: got %d; want %d", got, want)
		}
		if got, want := re.Reason, router.ReasonRateLimit; got != want {
			t.Errorf("reason: got %q; want %q", got, want)
		}
		if got := rec2.Header().Get("Retry-After"); got == "" {
			t.Errorf("missing Retry-After header")
		}
	})
}

func TestRateLimit(t *testing.T) {
	t.Parallel()

	mockHandler := router.HandlerFunc(func(e *router.Exchange) error {
		e.Status(http.StatusOK)
		return nil
	})

	limiter := rate.NewLimiter(0, 1)
	h := router.RateLimit(limiter)(mockHandler)

	// 1st request should succeed
	rec1 := httptest.NewRecorder()
	e1 := &router.Exchange{
		R: httptest.NewRequest(http.MethodGet, "/", nil),
		W: router.NewResponseWriter(rec1),
	}
	if err := h.ServeHTTP(e1); err != nil {
		t.Fatalf("first request should succeed: %v", err)
	}

	// 2nd request should fail
	rec2 := httptest.NewRecorder()
	e2 := &router.Exchange{
		R: httptest.NewRequest(http.MethodGet, "/", nil),
		W: router.NewResponseWriter(rec2),
	}
	err := h.ServeHTTP(e2)
	if err == nil {
		t.Fatal("second request should fail")
	}

	var re *router.Error
	if !errors.As(err, &re) {
		t.Fatalf("error type: got %T; want *router.Error", err)
	}
	if got, want := re.Status, http.StatusTooManyRequests; got != want {
		t.Errorf("status code: got %d; want %d", got, want)
	}
	if got := rec2.Header().Get("Retry-After"); got == "" {
		t.Errorf("missing Retry-After header")
	}
}
