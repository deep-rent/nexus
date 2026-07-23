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
	"encoding/json/v2"
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/deep-rent/nexus/net/router"
)

// Status enumerates the operational states of a dependency.
//
// Note that statuses are ranked by severity: [StatusHealthy] > [StatusDegraded]
// > [StatusSick]. This allows for direct comparison using standard operators.
type Status int

const (
	// StatusSick indicates the dependency is non-functional.
	StatusSick Status = iota
	// StatusDegraded indicates the dependency is functioning but with
	// issues (e.g., high latency).
	StatusDegraded
	// StatusHealthy indicates the dependency is functioning normally.
	StatusHealthy
)

// String returns the human-readable representation of the [Status].
func (s Status) String() string {
	switch s {
	case StatusHealthy:
		return "healthy"
	case StatusDegraded:
		return "degraded"
	case StatusSick:
		return "sick"
	default:
		return "unknown"
	}
}

// MarshalJSON implements the [json.Marshaler] interface, ensuring that the
// status is represented by its string name in JSON output rather than its
// underlying integer value.
func (s Status) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON implements the [json.Unmarshaler] interface. It converts a
// JSON string back into the corresponding [Status] integer constant. It returns
// an error if the string is not a recognized status.
func (s *Status) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch v {
	case "healthy":
		*s = StatusHealthy
	case "degraded":
		*s = StatusDegraded
	case "sick":
		*s = StatusSick
	default:
		return fmt.Errorf("invalid status: %s", v)
	}
	return nil
}

// Result holds the outcome of a health check execution.
type Result struct {
	// Status is the state of the check.
	Status Status `json:"status"`
	// Error contains a descriptive error message if the check failed.
	Error string `json:"error,omitempty"`
	// Timestamp records when this check was actually executed.
	Timestamp time.Time `json:"timestamp"`
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

// Kind is a bitmask used to categorize health checks for different probes.
type Kind int

const (
	// KindReadiness indicates the check should be evaluated by the readiness
	// probe.
	KindReadiness Kind = 1 << iota
	// KindLiveness indicates the check should be evaluated by the liveness
	// probe.
	KindLiveness
	// KindAll is a convenience mask that includes all kinds of checks.
	KindAll = KindReadiness | KindLiveness
)

// check wraps a registered check with its caching state and mutex.
type check struct {
	name    string             // specific identifier for the health check
	fn      CheckFunc          // health check callback to execute
	ttl     time.Duration      // time for which the result is considered fresh
	timeout time.Duration      // maximum execution time for the check
	kind    Kind               // bitmask of probes this check applies to
	sf      singleflight.Group // deduplicates concurrent executions
	mu      sync.RWMutex       // protects access to the cached last result
	last    Result             // most recently recorded result
}

// run executes the check or returns the cached result if the TTL hasn't
// expired. It protects against panics in the callback and deduplicates
// concurrent executions using singleflight.
func (c *check) run(ctx context.Context) Result {
	c.mu.RLock()
	if !c.last.Timestamp.IsZero() && time.Since(c.last.Timestamp) < c.ttl {
		res := c.last
		c.mu.RUnlock()
		return res
	}
	c.mu.RUnlock()

	ch := c.sf.DoChan("run", func() (any, error) {
		// Detach context to prevent client disconnects from poisoning the
		// cache.
		bgCtx := context.WithoutCancel(ctx)
		if c.timeout > 0 {
			var cancel context.CancelFunc
			bgCtx, cancel = context.WithTimeout(bgCtx, c.timeout)
			defer cancel()
		}

		var res Result
		func() {
			defer func() {
				if r := recover(); r != nil {
					res = Result{
						Status:    StatusSick,
						Error:     fmt.Sprintf("health check panicked: %v", r),
						Timestamp: time.Now(),
					}
				}
			}()

			status, err := c.fn(bgCtx)
			msg := ""
			if err != nil {
				msg = err.Error()
				// Default to sick if an error occurs but the status wasn't
				// explicitly set to degraded.
				if status != StatusDegraded {
					status = StatusSick
				}
			}

			res = Result{
				Status:    status,
				Error:     msg,
				Timestamp: time.Now(),
			}
		}()

		c.mu.Lock()
		c.last = res
		c.mu.Unlock()

		return res, nil
	})

	select {
	case <-ctx.Done():
		// Client disconnected or request timed out. Return a stale result if
		// available so we don't return an error while the check is successfully
		// updating in the background.
		c.mu.RLock()
		res := c.last
		c.mu.RUnlock()
		if res.Timestamp.IsZero() {
			return Result{
				Status:    StatusSick,
				Error:     ctx.Err().Error(),
				Timestamp: time.Now(),
			}
		}
		return res
	case res := <-ch:
		return res.Val.(Result)
	}
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
func (m *Monitor) Attach(
	name string,
	ttl time.Duration,
	fn CheckFunc,
	opts ...Option,
) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := &check{
		name: name,
		fn:   fn,
		ttl:  ttl,
		kind: KindAll,
	}
	for _, opt := range opts {
		opt(c)
	}
	m.checks[name] = c
}

// Detach unregisters a health check by name. If the check does not exist, this
// is a no-op.
func (m *Monitor) Detach(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.checks, name)
}

// run runs all registered checks matching the given kind concurrently and
// compiles the overall [Status] from the gathered results.
func (m *Monitor) run(
	ctx context.Context, kind Kind,
) (Status, map[string]Result) {
	m.mu.RLock()
	checks := make([]*check, 0, len(m.checks))
	for _, c := range m.checks {
		if c.kind&kind != 0 {
			checks = append(checks, c)
		}
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
			if res.Status < overall {
				overall = res.Status
			}
			mu.Unlock()
		}(c)
	}

	wg.Wait()
	return overall, results
}

// Live returns a handler that evaluates liveness checks.
// It returns HTTP 503 (Service Unavailable) if any check results in
// [StatusSick]. Otherwise, it returns HTTP 200.
func (m *Monitor) Live() router.HandlerFunc {
	return func(e *router.Exchange) error {
		overall, results := m.run(e.Context(), KindLiveness)

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

// Ready returns a handler that evaluates readiness checks.
// It returns HTTP 503 (Service Unavailable) if any check results in
// [StatusSick]. Otherwise, it returns HTTP 200.
func (m *Monitor) Ready() router.HandlerFunc {
	return func(e *router.Exchange) error {
		overall, results := m.run(e.Context(), KindReadiness)

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
	r.HandleFunc(http.MethodGet+" /health", m.Handler())
	r.HandleFunc(http.MethodGet+" /health/live", m.Live())
	r.HandleFunc(http.MethodGet+" /health/ready", m.Ready())
}
