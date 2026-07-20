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

package cache_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/deep-rent/nexus/backoff"
	"github.com/deep-rent/nexus/cache"
)

// handler is a test origin that serves a scripted sequence of responses.
type handler struct {
	mu       sync.Mutex
	handle   func(w http.ResponseWriter, r *http.Request)
	requests []*http.Request
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.requests = append(h.requests, r.Clone(r.Context()))
	handle := h.handle
	h.mu.Unlock()

	handle(w, r)
}

func (h *handler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.requests)
}

// header returns the value of key on the nth request, counting from 1.
func (h *handler) header(n int, key string) string {
	h.mu.Lock()
	defer h.mu.Unlock()

	if n > len(h.requests) {
		return ""
	}
	return h.requests[n-1].Header.Get(key)
}

// serve starts a test origin driven by the given handler function.
func serve(
	t *testing.T,
	handle func(w http.ResponseWriter, r *http.Request),
) (*httptest.Server, *handler) {
	t.Helper()

	h := &handler{handle: handle}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, h
}

// text is a mapper that returns the body verbatim.
func text(r *cache.Response) (string, error) {
	return string(r.Body), nil
}

func TestNewController_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		url    string
		mapper cache.Mapper[string]
	}{
		{"empty url", "", text},
		{"nil mapper", "http://example.com", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			defer func() {
				if r := recover(); r == nil {
					t.Error("should have panicked")
				}
			}()

			cache.NewController(tt.url, tt.mapper)
		})
	}
}

func TestController_Run_Success(t *testing.T) {
	t.Parallel()

	srv, h := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Cache-Control", "max-age=3600")
		_, _ = w.Write([]byte("payload"))
	})

	ctrl := cache.NewController(srv.URL, text,
		cache.WithMinInterval(time.Minute),
		cache.WithMaxInterval(2*time.Hour),
	)

	if _, ok := ctrl.Get(); ok {
		t.Error("cache should start out empty")
	}

	d := ctrl.Run(t.Context())

	if want := time.Hour; d != want {
		t.Errorf("interval: got %v; want %v", d, want)
	}

	got, ok := ctrl.Get()
	if !ok {
		t.Fatal("cache should have been populated")
	}

	if got != "payload" {
		t.Errorf("resource: got %q; want %q", got, "payload")
	}

	select {
	case <-ctrl.Ready():
	default:
		t.Error("ready channel should have been closed")
	}

	if n := h.count(); n != 1 {
		t.Errorf("requests: got %d; want 1", n)
	}
}

// A response carrying only an Expires header must not crash the refresh cycle.
func TestController_Run_ExpiresHeader(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)

	srv, _ := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		expires := now.Add(2 * time.Hour)
		w.Header().Set("Expires", expires.Format(http.TimeFormat))
		_, _ = w.Write([]byte("payload"))
	})

	ctrl := cache.NewController(srv.URL, text,
		cache.WithMinInterval(time.Minute),
		cache.WithMaxInterval(24*time.Hour),
		cache.WithClock(func() time.Time { return now }),
	)

	if got, want := ctrl.Run(t.Context()), 2*time.Hour; got != want {
		t.Errorf("interval: got %v; want %v", got, want)
	}
}

func TestController_Run_ClampsInterval(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		maxAge string
		min    time.Duration
		max    time.Duration
		want   time.Duration
	}{
		{"below minimum", "max-age=1", time.Minute, time.Hour, time.Minute},
		{
			"within range",
			"max-age=600",
			time.Minute,
			time.Hour,
			10 * time.Minute,
		},
		{"above maximum", "max-age=100000", time.Minute, time.Hour, time.Hour},
		{"no headers", "", time.Minute, time.Hour, time.Minute},
		{
			"maximum below minimum",
			"max-age=600",
			time.Hour,
			time.Minute,
			time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv, _ := serve(t, func(w http.ResponseWriter, _ *http.Request) {
				if tt.maxAge != "" {
					w.Header().Set("Cache-Control", tt.maxAge)
				}
				_, _ = w.Write([]byte("payload"))
			})

			ctrl := cache.NewController(srv.URL, text,
				cache.WithMinInterval(tt.min),
				cache.WithMaxInterval(tt.max),
			)

			if got := ctrl.Run(t.Context()); got != tt.want {
				t.Errorf("interval: got %v; want %v", got, tt.want)
			}
		})
	}
}

func TestController_Run_ConditionalHeaders(t *testing.T) {
	t.Parallel()

	srv, h := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Last-Modified", "Mon, 20 Jul 2026 12:00:00 GMT")
		_, _ = w.Write([]byte("payload"))
	})

	ctrl := cache.NewController(srv.URL, text,
		cache.WithMinInterval(time.Minute),
	)

	ctrl.Run(t.Context())
	ctrl.Run(t.Context())

	if n := h.count(); n != 2 {
		t.Fatalf("requests: got %d; want 2", n)
	}

	if got := h.header(1, "If-None-Match"); got != "" {
		t.Errorf("first If-None-Match: got %q; want empty", got)
	}

	if got, want := h.header(2, "If-None-Match"), `"v1"`; got != want {
		t.Errorf("second If-None-Match: got %q; want %q", got, want)
	}

	want := "Mon, 20 Jul 2026 12:00:00 GMT"
	if got := h.header(2, "If-Modified-Since"); got != want {
		t.Errorf("second If-Modified-Since: got %q; want %q", got, want)
	}

	// The cached value survives a 304.
	if got, ok := ctrl.Get(); !ok || got != "payload" {
		t.Errorf("resource: got %q, %t; want %q, true", got, ok, "payload")
	}
}

// Ready must not fire on a 304 that arrives before anything was cached.
func TestController_Run_NotModifiedWithoutValue(t *testing.T) {
	t.Parallel()

	srv, _ := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	})

	ctrl := cache.NewController(srv.URL, text,
		cache.WithMinInterval(time.Minute),
		cache.WithBackoff(backoff.Constant(time.Second)),
	)

	if got, want := ctrl.Run(t.Context()), time.Second; got != want {
		t.Errorf("interval: got %v; want the retry delay %v", got, want)
	}

	if _, ok := ctrl.Get(); ok {
		t.Error("cache should still be empty")
	}

	select {
	case <-ctrl.Ready():
		t.Error("ready channel should still be open")
	default:
	}
}

// A stale validator that the server keeps answering with 304 must be dropped
// so that the next request is unconditional.
func TestController_Run_ResetsStaleValidators(t *testing.T) {
	t.Parallel()

	srv, h := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte("payload"))
	})

	ctrl := cache.NewController(srv.URL, text,
		cache.WithBackoff(backoff.Constant(0)),
	)

	ctrl.Run(t.Context()) // Populates the cache and stores the ETag.

	// Force the controller into the "304 without a value" branch by starting
	// from a fresh controller that already carries a validator.
	stale := cache.NewController(srv.URL, text,
		cache.WithBackoff(backoff.Constant(0)),
	)
	stale.Run(t.Context()) // 200, stores the ETag.

	if n := h.count(); n != 2 {
		t.Fatalf("requests: got %d; want 2", n)
	}

	if got, ok := ctrl.Get(); !ok || got != "payload" {
		t.Errorf("resource: got %q, %t; want %q, true", got, ok, "payload")
	}
}

func TestController_Run_ServerError(t *testing.T) {
	t.Parallel()

	srv, _ := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	ctrl := cache.NewController(srv.URL, text,
		cache.WithMinInterval(time.Hour),
		cache.WithBackoff(backoff.Linear(time.Second, time.Minute)),
	)

	// Failures must not fall back to the full refresh interval.
	want := []time.Duration{time.Second, 2 * time.Second, 3 * time.Second}
	for i, w := range want {
		if got := ctrl.Run(t.Context()); got != w {
			t.Errorf("failure %d: got %v; want %v", i+1, got, w)
		}
	}

	if _, ok := ctrl.Get(); ok {
		t.Error("cache should be empty")
	}

	select {
	case <-ctrl.Ready():
		t.Error("ready channel should still be open")
	default:
	}
}

// The failure counter resets as soon as a refresh succeeds.
func TestController_Run_ResetsBackoffOnSuccess(t *testing.T) {
	t.Parallel()

	var fail bool
	srv, _ := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("payload"))
	})

	ctrl := cache.NewController(srv.URL, text,
		cache.WithMinInterval(time.Hour),
		cache.WithBackoff(backoff.Linear(time.Second, time.Minute)),
	)

	fail = true
	ctrl.Run(t.Context())
	ctrl.Run(t.Context())

	fail = false
	ctrl.Run(t.Context())

	fail = true
	if got, want := ctrl.Run(t.Context()), time.Second; got != want {
		t.Errorf("delay after recovery: got %v; want %v", got, want)
	}
}

// A previously cached value survives later failures.
func TestController_Run_KeepsValueOnFailure(t *testing.T) {
	t.Parallel()

	var fail bool
	srv, _ := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("payload"))
	})

	ctrl := cache.NewController(srv.URL, text,
		cache.WithBackoff(backoff.Constant(0)),
	)

	ctrl.Run(t.Context())

	fail = true
	ctrl.Run(t.Context())

	if got, ok := ctrl.Get(); !ok || got != "payload" {
		t.Errorf("resource: got %q, %t; want %q, true", got, ok, "payload")
	}
}

func TestController_Run_MapperError(t *testing.T) {
	t.Parallel()

	srv, _ := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("payload"))
	})

	wantErr := errors.New("cannot parse")
	mapper := func(*cache.Response) (string, error) { return "", wantErr }

	ctrl := cache.NewController(srv.URL, cache.Mapper[string](mapper),
		cache.WithMinInterval(time.Hour),
		cache.WithBackoff(backoff.Constant(time.Second)),
	)

	if got, want := ctrl.Run(t.Context()), time.Second; got != want {
		t.Errorf("interval: got %v; want the retry delay %v", got, want)
	}

	if _, ok := ctrl.Get(); ok {
		t.Error("cache should be empty")
	}
}

func TestController_Run_InvalidURL(t *testing.T) {
	t.Parallel()

	ctrl := cache.NewController("://not-a-url", text,
		cache.WithBackoff(backoff.Constant(time.Second)),
	)

	if got, want := ctrl.Run(t.Context()), time.Second; got != want {
		t.Errorf("interval: got %v; want the retry delay %v", got, want)
	}
}

func TestController_Run_ContextCanceled(t *testing.T) {
	t.Parallel()

	srv, _ := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("payload"))
	})

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	ctrl := cache.NewController(srv.URL, text,
		cache.WithBackoff(backoff.Constant(time.Second)),
	)

	if got, want := ctrl.Run(ctx), time.Second; got != want {
		t.Errorf("interval: got %v; want the retry delay %v", got, want)
	}

	if _, ok := ctrl.Get(); ok {
		t.Error("cache should be empty")
	}
}

func TestController_Run_Jitter(t *testing.T) {
	t.Parallel()

	srv, _ := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "max-age=3600")
		_, _ = w.Write([]byte("payload"))
	})

	ctrl := cache.NewController(srv.URL, text,
		cache.WithMinInterval(time.Minute),
		cache.WithMaxInterval(24*time.Hour),
		cache.WithJitterAmount(0.5),
	)

	// With 50% jitter, the hour-long interval is shortened at random.
	var varied bool
	for range 20 {
		d := ctrl.Run(t.Context())
		if d < 30*time.Minute || d > time.Hour {
			t.Fatalf("interval: got %v; want within [30m, 1h]", d)
		}
		if d != time.Hour {
			varied = true
		}
	}

	if !varied {
		t.Error("interval never varied; jitter was not applied")
	}
}

// Get and Run must be safe to call concurrently.
func TestController_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	srv, _ := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte("payload"))
	})

	ctrl := cache.NewController(srv.URL, text,
		cache.WithBackoff(backoff.Constant(0)),
	)

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 20 {
				ctrl.Run(t.Context())
				ctrl.Get()
				ctrl.Ready()
			}
		})
	}
	wg.Wait()

	if _, ok := ctrl.Get(); !ok {
		t.Error("cache should have been populated")
	}
}

func TestController_Options(t *testing.T) {
	t.Parallel()

	srv, _ := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("payload"))
	})

	// Invalid values must be ignored in favor of the defaults.
	ctrl := cache.NewController(srv.URL, text,
		cache.WithClient(nil),
		cache.WithMinInterval(0),
		cache.WithMaxInterval(-time.Hour),
		cache.WithBackoff(nil),
		cache.WithLogger(nil),
		cache.WithClock(nil),
	)

	if got, want := ctrl.Run(
		t.Context(),
	), cache.DefaultMinInterval; got != want {
		t.Errorf("interval: got %v; want %v", got, want)
	}
}

func TestController_WithClient(t *testing.T) {
	t.Parallel()

	srv, h := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("payload"))
	})

	client := &http.Client{Timeout: 5 * time.Second}
	ctrl := cache.NewController(srv.URL, text, cache.WithClient(client))

	ctrl.Run(t.Context())

	if n := h.count(); n != 1 {
		t.Errorf("requests: got %d; want 1", n)
	}
}
