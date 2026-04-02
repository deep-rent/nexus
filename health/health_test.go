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
	"encoding/json"
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
					return "", errors.New("fail")
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
				t.Errorf("ServeHTTP() status code = %d; want %d", got, want)
			}

			var rep health.Report
			if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
				t.Fatalf("json.Unmarshal(body) = %v; want nil", err)
			}

			if got, want := rep.Status, tt.wantStatus; got != want {
				t.Errorf("Report.Status = %q; want %q", got, want)
			}

			if got, want := len(rep.Checks), len(tt.checks); got != want {
				t.Errorf("len(Report.Checks) = %d; want %d", got, want)
			}

			now := time.Now()
			for name, res := range rep.Checks {
				if res.Timestamp.IsZero() {
					t.Errorf("Check %q timestamp is zero; want non-zero", name)
				}

				diff := now.Sub(res.Timestamp)
				if diff < 0 {
					diff = -diff
				}
				if diff > 2*time.Second {
					t.Errorf("Check %q timestamp = %v; want within 2s of %v",
						name, res.Timestamp, now)
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
	m.Attach("failure", 0, chk)

	r := router.New()
	m.Mount(r)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	r.ServeHTTP(w, req)

	if got, want := w.Code, http.StatusOK; got != want {
		t.Errorf("ServeHTTP() status code = %d; want %d", got, want)
	}

	var rep health.Report
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
		t.Fatalf("json.Unmarshal(body) = %v; want nil", err)
	}

	if got, want := rep.Status, health.StatusHealthy; got != want {
		t.Errorf("Report.Status = %q; want %q", got, want)
	}
}

func TestMonitor_Caching(t *testing.T) {
	t.Parallel()

	m := health.NewMonitor()
	var calls int32

	chk := func(ctx context.Context) (health.Status, error) {
		atomic.AddInt32(&calls, 1)
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

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("atomic.LoadInt32(&calls) = %d; want 1 (must use cache)", got)
	}

	time.Sleep(60 * time.Millisecond)
	r.ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/health", nil),
	)

	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("atomic.LoadInt32(&calls) = %d; want 2 (must refresh cache)", got)
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
		t.Fatalf("json.Unmarshal(body) = %v", err)
	}

	if _, ok := rep1.Checks["tmp"]; !ok {
		t.Errorf("Report.Checks contains %q; want true", "tmp")
	}

	m.Detach("tmp")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/health", nil))
	var rep2 health.Report
	if err := json.Unmarshal(w2.Body.Bytes(), &rep2); err != nil {
		t.Fatalf("json.Unmarshal(body) = %v", err)
	}

	if _, ok := rep2.Checks["tmp"]; ok {
		t.Errorf("Report.Checks contains %q; want false", "tmp")
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
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			r.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Errorf("ServeHTTP() status code = %d; want 200", w.Code)
			}
		}()
	}
	wg.Wait()
}

func TestMonitor_ContextPropagation(t *testing.T) {
	t.Parallel()

	m := health.NewMonitor()
	received := make(chan struct{})

	m.Attach("ctx_test", 0, func(ctx context.Context) (health.Status, error) {
		select {
		case <-ctx.Done():
			close(received)
			return health.StatusSick, ctx.Err()
		case <-time.After(100 * time.Millisecond):
			return health.StatusHealthy, nil
		}
	})

	r := router.New()
	m.Mount(r)

	ctx, cancel := context.WithCancel(t.Context())
	req := httptest.NewRequest(http.MethodGet, "/health", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	cancel()
	r.ServeHTTP(w, req)

	select {
	case <-received:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("CheckFunc did not receive context cancellation")
	}
}
