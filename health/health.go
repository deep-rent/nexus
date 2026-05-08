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

// Package health provides a registry and HTTP handlers for application health
// monitoring.
//
// It allows for the registration of pluggable health checks with built-in
// TTL-based caching to prevent overloading downstream dependencies. The package
// handles the orchestration of these checks, providing thread-safe execution
// and aggregation of results into standardized [Report] formats suitable for
// automated monitoring systems and human inspection.
//
// # Usage
//
// To use the health monitor, create a new instance, attach your dependency
// checks, and mount the handlers to your router.
//
// Example:
//
//	monitor := health.NewMonitor()
//
//	// Register a check with a 5-second minimum delay between invocations.
//	monitor.Attach("database", 5*time.Second, check.Ping(db))
//
//	// Mount the standard endpoints (/health, /health/live, /health/ready)
//	// to a router.Router instance.
//	monitor.Mount(r)
package health

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/deep-rent/nexus/router"
)

// Status enumerates the operational states of a dependency.
type Status string

const (
	// StatusHealthy indicates the dependency is functioning normally.
	StatusHealthy Status = "healthy"
	// StatusDegraded indicates the dependency is functioning but with
	// issues (e.g., high latency).
	StatusDegraded Status = "degraded"
	// StatusSick indicates the dependency is non-functional.
	StatusSick Status = "sick"
)

// Result holds the outcome of a health check execution.
type Result struct {
	// Status is the state of the check.
	Status Status `json:"status"`
	// Error contains a descriptive error message if the check failed.
	Error string `json:"error,omitempty"`
	// Timestamp records when this check was actually executed.
	Timestamp time.Time `json:"timestamp,format:unix"`
}

// Report represents the aggregated outcome of all registered health checks.
type Report struct {
	// Status is the overall health state of the application.
	Status Status `json:"status"`
	// Checks maps the name of each registered check to its specific [Result].
	Checks map[string]Result `json:"checks"`
}

// CheckFunc defines the signature for a pluggable health check. It receives
// the request context to allow for cancellation and should return the
// perceived [Status] and an error if applicable.
type CheckFunc func(ctx context.Context) (Status, error)

// check wraps a registered check with its caching state and mutex.
type check struct {
	// name is the identifier for the health check.
	name string
	// fn is the [CheckFunc] to execute.
	fn CheckFunc
	// ttl is the duration for which the [Result] is considered fresh.
	ttl time.Duration
	// mu protects access to the cached last result.
	mu sync.RWMutex
	// last is the most recently recorded [Result].
	last Result
}

// run executes the check or returns the cached result if the TTL hasn't
// expired. It protects against panics in the callback.
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

// Monitor manages the registry of health checks and provides the
// [router]-compatible handlers. It is safe for concurrent use.
type Monitor struct {
	// mu protects access to the internal map of checks.
	mu sync.RWMutex
	// checks stores registered health checks indexed by name.
	checks map[string]*check
}

// NewMonitor creates a fresh [Monitor] instance.
func NewMonitor() *Monitor {
	return &Monitor{
		checks: make(map[string]*check),
	}
}

// Attach registers a new health check under the given name. If a check with
// the same name already exists, it is replaced.
//
// The name should be formatted in snake_case (e.g., "redis_primary").
// The TTL (Time-To-Live) parameter defines the minimum duration between
// consecutive executions of the [CheckFunc]; subsequent calls within this
// window return the cached [Result] to prevent overloading the dependency.
func (m *Monitor) Attach(name string, ttl time.Duration, fn CheckFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checks[name] = &check{
		name: name,
		fn:   fn,
		ttl:  ttl,
	}
}

// Detach unregisters a health check by name. If the check does not exist, this
// is a no-op.
func (m *Monitor) Detach(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.checks, name)
}

// run runs all registered checks concurrently and compiles the overall [Status]
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

// Live returns a handler that indicates if the application process is alive.
// It always returns [StatusHealthy] and HTTP 200 without checking dependencies,
// serving as a basic liveness probe to detect process hangs.
func (m *Monitor) Live() router.HandlerFunc {
	return func(e *router.Exchange) error {
		return e.JSON(http.StatusOK, Report{
			Status: StatusHealthy,
		})
	}
}

// Ready returns a handler that evaluates all registered checks.
// It returns HTTP 503 (Service Unavailable) if any check results in
// [StatusSick]. Otherwise, it returns HTTP 200.
func (m *Monitor) Ready() router.HandlerFunc {
	return func(e *router.Exchange) error {
		overall, results := m.run(e.Context())

		code := http.StatusOK
		if overall == StatusSick {
			code = http.StatusServiceUnavailable
		}

		return e.JSON(code, Report{
			Status: overall,
			Checks: results,
		})
	}
}

// Handler is an alias for [Monitor.Ready]. It provides a detailed JSON
// breakdown of all checks, suitable for monitoring scrapers and dashboards.
func (m *Monitor) Handler() router.HandlerFunc {
	return m.Ready()
}

// Mount registers the standard health check routes on the provided
// [router.Router].
//
// It exposes:
//   - GET /health: Detailed summary of all checks.
//   - GET /health/live: Shallow liveness probe.
//   - GET /health/ready: Deep readiness probe.
func (m *Monitor) Mount(r *router.Router) {
	r.HandleFunc("GET /health", m.Handler())
	r.HandleFunc("GET /health/live", m.Live())
	r.HandleFunc("GET /health/ready", m.Ready())
}
