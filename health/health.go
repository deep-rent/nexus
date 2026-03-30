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

package health

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/deep-rent/nexus/router"
)

// Status represents the operational state of a dependency.
type Status string

const (
	StatusHealthy  Status = "healthy"
	StatusDegraded Status = "degraded"
	StatusSick     Status = "sick"
)

// Result holds the outcome of a health check execution.
// TODO: Update to encoding/json/v2
type Result struct {
	Status    Status    `json:"status"`
	Error     string    `json:"error,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// CheckFunc is the signature for a pluggable health check.
type CheckFunc func(ctx context.Context) (Status, error)

// check wraps a registered check with its caching state and mutex.
type check struct {
	name string
	fn   CheckFunc
	ttl  time.Duration
	mu   sync.RWMutex
	last Result
}

// run executes the check or returns the cached result if the TTL hasn't
// expired.
func (c *check) run(ctx context.Context) (res Result) {
	c.mu.RLock()
	if time.Since(c.last.Timestamp) < c.ttl {
		res := c.last
		c.mu.RUnlock()
		return res
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	// Double-check the cache after acquiring the write lock.
	if time.Since(c.last.Timestamp) < c.ttl {
		return c.last
	}

	defer func() {
		if r := recover(); r != nil {
			c.last = Result{
				Status:    StatusSick,
				Error:     fmt.Sprintf("health check panicked: %v", r),
				Timestamp: time.Now(),
			}
			res = c.last
		}
	}()

	status, err := c.fn(ctx)
	msg := ""
	if err != nil {
		msg = err.Error()
		// Default to sick if an error occurs but the status wasn't explicitly set
		// to degraded.
		if status != StatusDegraded {
			status = StatusSick
		}
	}

	c.last = Result{
		Status:    status,
		Error:     msg,
		Timestamp: time.Now(),
	}
	return c.last
}

// Monitor manages health checks and provides HTTP handlers.
type Monitor struct {
	mu     sync.RWMutex
	checks map[string]*check
}

// NewMonitor creates a fresh health monitor instance.
func NewMonitor() *Monitor {
	return &Monitor{
		checks: make(map[string]*check),
	}
}

// Register adds a new health check with a minimum delay (TTL) between
// consecutive executions. If a check under the given name already exists, it
// will be replaced.
func (m *Monitor) Register(name string, ttl time.Duration, fn CheckFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checks[name] = &check{
		name: name,
		fn:   fn,
		ttl:  ttl,
	}
}

// Unregister removes a health check by name. If the check does not exist,
// this is a no-op.
func (m *Monitor) Unregister(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.checks, name)
}

// run runs all registered checks concurrently and compiles the overall status
// from the gathered results.
func (m *Monitor) run(ctx context.Context) (Status, map[string]Result) {
	m.mu.RLock()
	checks := make([]*check, 0, len(m.checks))
	for _, c := range m.checks {
		checks = append(checks, c)
	}
	m.mu.RUnlock()

	results := make(map[string]Result, len(checks))
	overall := StatusHealthy

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, c := range checks {
		wg.Add(1)
		go func(current *check) {
			defer wg.Done()
			res := current.run(ctx)

			mu.Lock()
			results[current.name] = res
			if res.Status == StatusSick {
				overall = StatusSick
			} else if res.Status == StatusDegraded && overall == StatusHealthy {
				overall = StatusDegraded
			}
			mu.Unlock()
		}(c)
	}

	wg.Wait()
	return overall, results
}

// Live indicates whether the application process is running.
// It does not evaluate external dependencies to prevent orchestration loops
// from killing the pod.
func (m *Monitor) Live() router.HandlerFunc {
	return func(e *router.Exchange) error {
		return e.JSON(http.StatusOK, map[string]Status{"status": StatusHealthy})
	}
}

// Ready evaluates checks to determine if the app can serve traffic.
// Returns HTTP 503 if any dependency is sick.
func (m *Monitor) Ready() router.HandlerFunc {
	return func(e *router.Exchange) error {
		overall, results := m.run(e.Context())

		code := http.StatusOK
		if overall == StatusSick {
			code = http.StatusServiceUnavailable
		}

		return e.JSON(code, map[string]any{
			"status": overall,
			"checks": results,
		})
	}
}

// Handler provides the exact same detailed breakdown as readiness,
// but is intended for operational dashboards and monitoring scrapers.
func (m *Monitor) Handler() router.HandlerFunc {
	return m.Ready()
}

// Mount registers the standard health check endpoints on the provided router.
func (m *Monitor) Mount(r *router.Router) {
	r.HandleFunc("GET /health", m.Handler())
	r.HandleFunc("GET /health/live", m.Live())
	r.HandleFunc("GET /health/ready", m.Ready())
}
