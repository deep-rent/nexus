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

package health_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deep-rent/nexus/health"
	"github.com/deep-rent/nexus/router"
)

func TestMonitor_Ready(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		checks     map[string]health.CheckFunc
		wantStatus health.Status
		wantCode   int
	}{
		{
			name: "all healthy",
			checks: map[string]health.CheckFunc{
				"db": func(ctx context.Context) (health.Status, error) {
					return health.StatusHealthy, nil
				},
			},
			wantStatus: health.StatusHealthy,
			wantCode:   http.StatusOK,
		},
		{
			name: "one degraded",
			checks: map[string]health.CheckFunc{
				"db": func(ctx context.Context) (health.Status, error) {
					return health.StatusHealthy, nil
				},
				"redis": func(ctx context.Context) (health.Status, error) {
					return health.StatusDegraded, nil
				},
			},
			wantStatus: health.StatusDegraded,
			wantCode:   http.StatusOK,
		},
		{
			name: "one sick",
			checks: map[string]health.CheckFunc{
				"db": func(ctx context.Context) (health.Status, error) {
					return health.StatusHealthy, nil
				},
				"redis": func(ctx context.Context) (health.Status, error) {
					return health.StatusSick, nil
				},
			},
			wantStatus: health.StatusSick,
			wantCode:   http.StatusServiceUnavailable,
		},
		{
			name: "error becomes sick",
			checks: map[string]health.CheckFunc{
				"api": func(ctx context.Context) (health.Status, error) {
					// Use 0 or health.StatusSick since Status is now an int
					return 0, errors.New("fail")
				},
			},
			wantStatus: health.StatusSick,
			wantCode:   http.StatusServiceUnavailable,
		},
		{
			name: "panic becomes sick",
			checks: map[string]health.CheckFunc{
				"panic": func(ctx context.Context) (health.Status, error) {
					panic("boom")
				},
			},
			wantStatus: health.StatusSick,
			wantCode:   http.StatusServiceUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := health.NewMonitor()
			for n, fn := range tt.checks {
				m.Attach(n, 0, fn)
			}

			r := router.New()
			m.Mount(r)

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
			r.ServeHTTP(w, req)

			if got, want := w.Code, tt.wantCode; got != want {
				t.Errorf("status code: got %d; want %d", got, want)
			}

			var rep health.Report
			if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
				t.Fatalf(
					"unmarshaling body: should not have returned an error: %v",
					err,
				)
			}

			if got, want := rep.Status, tt.wantStatus; got != want {
				t.Errorf("report status: got %q; want %q", got, want)
			}

			if got, want := len(rep.Checks), len(tt.checks); got != want {
				t.Errorf("number of checks: got %d; want %d", got, want)
			}

			now := time.Now()
			for name, res := range rep.Checks {
				if res.Timestamp.IsZero() {
					t.Errorf(
						"timestamp for check %q is zero; want non-zero",
						name,
					)
				}

				diff := now.Sub(res.Timestamp)
				if diff < 0 {
					diff = -diff
				}
				if diff > 2*time.Second {
					t.Errorf(
						"for check %q: got timestamp %v; want within 2s of %v",
						name,
						res.Timestamp,
						now,
					)
				}
			}
		})
	}
}

func TestMonitor_Live(t *testing.T) {
	t.Parallel()

	m := health.NewMonitor()
	chk := func(ctx context.Context) (health.Status, error) {
		return health.StatusSick, nil
	}
	m.Attach("failure", 0, chk, health.WithKind(health.KindReadiness))

	r := router.New()
	m.Mount(r)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	r.ServeHTTP(w, req)

	if got, want := w.Code, http.StatusOK; got != want {
		t.Errorf("status code: got %d; want %d", got, want)
	}

	var rep health.Report
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
		t.Fatalf(
			"unmarshaling body: should not have returned an error: %v",
			err,
		)
	}

	if got, want := rep.Status, health.StatusHealthy; got != want {
		t.Errorf("report status: got %v; want %v", got, want)
	}
}

func TestMonitor_Caching(t *testing.T) {
	t.Parallel()

	m := health.NewMonitor()
	var calls atomic.Int32

	chk := func(ctx context.Context) (health.Status, error) {
		calls.Add(1)
		return health.StatusHealthy, nil
	}

	m.Attach("cached", 50*time.Millisecond, chk)

	r := router.New()
	m.Mount(r)

	for range 5 {
		r.ServeHTTP(
			httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, "/health", nil),
		)
	}

	if got := calls.Load(); got != 1 {
		t.Errorf("calls while cached: got %d; want 1", got)
	}

	time.Sleep(60 * time.Millisecond)
	r.ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/health", nil),
	)

	if got := calls.Load(); got != 2 {
		t.Errorf("calls after cache expiry: got %d; want 2", got)
	}
}

func TestMonitor_CachePoisoning(t *testing.T) {
	t.Parallel()

	m := health.NewMonitor()

	started := make(chan struct{})
	chk := func(ctx context.Context) (health.Status, error) {
		close(started)
		time.Sleep(100 * time.Millisecond) // Simulate slow check
		return health.StatusHealthy, nil
	}

	m.Attach("slow", 1*time.Minute, chk)

	r := router.New()
	m.Mount(r)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	ctx, cancel := context.WithCancel(req.Context())
	req = req.WithContext(ctx)

	go func() {
		<-started
		cancel() // Cancel the HTTP request context while the check is running
	}()

	w := httptest.NewRecorder()
	r.ServeHTTP(
		w,
		req,
	) // This should return immediately with a generic error due to context cancellation.

	// The background check should still complete successfully.
	time.Sleep(200 * time.Millisecond)

	// Second request should return a cached healthy result
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/health", nil))

	var rep health.Report
	if err := json.Unmarshal(w2.Body.Bytes(), &rep); err != nil {
		t.Fatalf("unmarshaling body: %v", err)
	}

	if got, want := rep.Status, health.StatusHealthy; got != want {
		t.Errorf(
			"report status: got %v; want %v (cache was poisoned)",
			got,
			want,
		)
	}
}

func TestMonitor_Timeout(t *testing.T) {
	t.Parallel()

	m := health.NewMonitor()

	chk := func(ctx context.Context) (health.Status, error) {
		<-ctx.Done() // Block until context is canceled by timeout
		return health.StatusHealthy, ctx.Err()
	}

	m.Attach(
		"timeout",
		1*time.Minute,
		chk,
		health.WithTimeout(10*time.Millisecond),
	)

	r := router.New()
	m.Mount(r)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))

	var rep health.Report
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
		t.Fatalf("unmarshaling body: %v", err)
	}

	if got, want := rep.Status, health.StatusSick; got != want {
		t.Errorf("report status: got %v; want %v", got, want)
	}
	if msg := rep.Checks["timeout"].Error; msg != "context deadline exceeded" {
		t.Errorf("expected context deadline exceeded, got: %q", msg)
	}
}

func TestMonitor_Lifecycle(t *testing.T) {
	t.Parallel()

	m := health.NewMonitor()
	m.Attach("tmp", 0, func(ctx context.Context) (health.Status, error) {
		return health.StatusHealthy, nil
	})

	r := router.New()
	m.Mount(r)

	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, httptest.NewRequest(http.MethodGet, "/health", nil))
	var rep1 health.Report
	if err := json.Unmarshal(w1.Body.Bytes(), &rep1); err != nil {
		t.Fatalf("before detach: should not have returned an error: %v", err)
	}

	if _, ok := rep1.Checks["tmp"]; !ok {
		t.Errorf("checks should contain %q before detach", "tmp")
	}

	m.Detach("tmp")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/health", nil))
	var rep2 health.Report
	if err := json.Unmarshal(w2.Body.Bytes(), &rep2); err != nil {
		t.Fatalf("after detach: should not have returned an error: %v", err)
	}

	if _, ok := rep2.Checks["tmp"]; ok {
		t.Errorf("checks should not contain %q after detach", "tmp")
	}
}

func TestMonitor_Concurrency(t *testing.T) {
	t.Parallel()

	m := health.NewMonitor()
	m.Attach("a", 0, func(ctx context.Context) (health.Status, error) {
		return health.StatusHealthy, nil
	})
	m.Attach("b", 0, func(ctx context.Context) (health.Status, error) {
		return health.StatusHealthy, nil
	})

	r := router.New()
	m.Mount(r)

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			r.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Errorf("status code: got %d; want 200", w.Code)
			}
		})
	}
	wg.Wait()
}

func TestStatus_Serialization(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		status   health.Status
		expected string
	}{
		{"healthy", health.StatusHealthy, `"healthy"`},
		{"degraded", health.StatusDegraded, `"degraded"`},
		{"sick", health.StatusSick, `"sick"`},
	}

	for _, tt := range tests {
		t.Run("Marshal_"+tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.status)
			if err != nil {
				t.Fatalf("should not have returned an error: %v", err)
			}
			if string(got) != tt.expected {
				t.Errorf("got %s; want %s", string(got), tt.expected)
			}
		})

		t.Run("Unmarshal_"+tt.name, func(t *testing.T) {
			var got health.Status
			if err := json.Unmarshal([]byte(tt.expected), &got); err != nil {
				t.Fatalf("should not have returned an error: %v", err)
			}
			if got != tt.status {
				t.Errorf("got %v; want %v", got, tt.status)
			}
		})
	}

	t.Run("Unmarshal_Invalid", func(t *testing.T) {
		var got health.Status
		err := json.Unmarshal([]byte(`"unknown_status"`), &got)
		if err == nil {
			t.Error("should have returned an error")
		}
	})
}

func TestStatus_String(t *testing.T) {
	t.Parallel()
	if got, want := health.StatusHealthy.String(), "healthy"; got != want {
		t.Errorf("healthy status: got %q; want %q", got, want)
	}
	if got, want := health.Status(-1).String(), "unknown"; got != want {
		t.Errorf("undefined status: got %q; want %q", got, want)
	}
}
