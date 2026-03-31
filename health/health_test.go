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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/deep-rent/nexus/health"
	"github.com/deep-rent/nexus/router"
)

func TestMonitor_Ready(t *testing.T) {
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

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := health.NewMonitor()
			for n, fn := range tc.checks {
				m.Attach(n, 0, fn)
			}

			r := router.New()
			m.Mount(r)

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
			r.ServeHTTP(w, req)

			var rep health.Report
			err := json.Unmarshal(w.Body.Bytes(), &rep)
			require.NoError(t, err)

			assert.Equal(t, tc.wantCode, w.Code)
			assert.Equal(t, tc.wantStatus, rep.Status)
			assert.Len(t, rep.Checks, len(tc.checks))

			for name, res := range rep.Checks {
				ts := res.Timestamp
				assert.False(
					t,
					ts.IsZero(),
					"timestamp for check %q must be set",
					name,
				)
				assert.WithinDuration(
					t,
					time.Now(),
					ts,
					2*time.Second,
					"timestamp for check %q must be within 2s of now",
					name,
				)
			}
		})
	}
}

func TestMonitor_Live(t *testing.T) {
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

	assert.Equal(t, http.StatusOK, w.Code)

	var rep health.Report
	json.Unmarshal(w.Body.Bytes(), &rep)
	assert.Equal(t, health.StatusHealthy, rep.Status)
}

func TestMonitor_Caching(t *testing.T) {
	m := health.NewMonitor()
	var calls int32

	chk := func(ctx context.Context) (health.Status, error) {
		atomic.AddInt32(&calls, 1)
		return health.StatusHealthy, nil
	}

	m.Attach("cached", 50*time.Millisecond, chk)

	r := router.New()
	m.Mount(r)

	// Call multiple times rapidly:
	for range 5 {
		r.ServeHTTP(
			httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, "/health", nil),
		)
	}

	assert.Equal(
		t,
		int32(1),
		atomic.LoadInt32(&calls),
		"must use cached result",
	)

	// Wait for TTL:
	time.Sleep(60 * time.Millisecond)
	r.ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/health", nil),
	)

	assert.Equal(
		t,
		int32(2),
		atomic.LoadInt32(&calls),
		"must refresh after TTL",
	)
}

func TestMonitor_Lifecycle(t *testing.T) {
	m := health.NewMonitor()
	m.Attach("tmp", 0, func(ctx context.Context) (health.Status, error) {
		return health.StatusHealthy, nil
	})

	r := router.New()
	m.Mount(r)

	// Verify it exists:
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, httptest.NewRequest(http.MethodGet, "/health", nil))
	var rep1 health.Report
	json.Unmarshal(w1.Body.Bytes(), &rep1)
	assert.Contains(t, rep1.Checks, "tmp")

	// Detach and verify gone:
	m.Detach("tmp")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/health", nil))
	var rep2 health.Report
	json.Unmarshal(w2.Body.Bytes(), &rep2)
	assert.NotContains(t, rep2.Checks, "tmp")
}

func TestMonitor_Concurrency(t *testing.T) {
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
			assert.Equal(t, http.StatusOK, w.Code)
		})
	}
	wg.Wait()
}

func TestMonitor_ContextPropagation(t *testing.T) {
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

	// Create a context that we can cancel:
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/health", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	// Cancel the context immediately to simulate a client disconnect:
	cancel()
	r.ServeHTTP(w, req)

	select {
	case <-received:
		// Success: the check function saw the cancellation:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("CheckFunc did not receive context cancellation")
	}
}
