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

package middleware

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/deep-rent/nexus/metrics"
)

// RequestDuration is the name of the histogram recorded by [Measure].
const RequestDuration = "http_server_request_duration_seconds"

// routeKey is the context key under which [Measure] stores its route holder.
type routeKey struct{}

// routeHolder carries the matched route pattern by reference.
//
// [http.ServeMux] stamps the pattern onto the request it receives, but any
// middleware between [Measure] and the mux that calls
// [http.Request.WithContext] hands the mux a shallow clone, hiding the
// pattern from the request Measure holds. A pointer in the context survives
// every clone.
type routeHolder struct {
	pattern string
}

// SetRoute records the matched route pattern for the [Measure] middleware,
// which uses it to tag the request duration histogram. It is a no-op if the
// request is not being measured.
//
// The router package calls this with the matched [http.ServeMux] pattern;
// custom handlers only need it when they resolve routes themselves.
func SetRoute(ctx context.Context, pattern string) {
	if holder, ok := ctx.Value(routeKey{}).(*routeHolder); ok {
		holder.pattern = pattern
	}
}

// GetRoute returns the route pattern recorded via [SetRoute], or the empty
// string if none was recorded.
func GetRoute(ctx context.Context) string {
	if holder, ok := ctx.Value(routeKey{}).(*routeHolder); ok {
		return holder.pattern
	}
	return ""
}

// measureConfig holds the configuration for the [Measure] middleware.
type measureConfig struct {
	registry *metrics.Registry
	filter   func(r *http.Request) bool
	skip     map[string]struct{}
}

// MeasureOption configures the [Measure] middleware.
type MeasureOption func(*measureConfig)

// WithRegistry sets the destination registry. It defaults to
// [metrics.DefaultRegistry]. A nil value is ignored.
func WithRegistry(reg *metrics.Registry) MeasureOption {
	return func(c *measureConfig) {
		if reg != nil {
			c.registry = reg
		}
	}
}

// WithFilter limits measurement to requests for which keep returns true.
// Filtered requests pass through unrecorded. A nil function is ignored.
func WithFilter(keep func(r *http.Request) bool) MeasureOption {
	return func(c *measureConfig) {
		if keep != nil {
			c.filter = keep
		}
	}
}

// WithSkip excludes requests whose URL path exactly matches one of the
// given paths from measurement. It is a convenience for high-frequency
// probe endpoints, such as the ones mounted by the health package:
//
//	middleware.Measure(middleware.WithSkip(
//		"/health", "/health/live", "/health/ready",
//	))
//
// For more elaborate rules, use [WithFilter].
func WithSkip(paths ...string) MeasureOption {
	return func(c *measureConfig) {
		if c.skip == nil {
			c.skip = make(map[string]struct{}, len(paths))
		}
		for _, p := range paths {
			c.skip[p] = struct{}{}
		}
	}
}

// Measure returns a middleware [Pipe] that records every HTTP request in
// the [RequestDuration] histogram, tagged with the method, the matched
// route pattern, and the response status code.
//
// The route becomes known only after the mux has matched: it is either
// recorded via [SetRoute] (the router package does this) or read from
// [http.Request.Pattern] when Measure sits directly in front of the mux,
// and is empty otherwise. Tagging by pattern rather than raw path keeps the
// metric cardinality bounded.
//
// A panic in a downstream handler is recorded as a 500 and re-raised, so
// [Recover] must still sit outside Measure in the chain:
//
//	middleware.Chain(mux,
//		middleware.Recover(logger),
//		middleware.Measure(),
//		middleware.RequestID(),
//		middleware.Log(logger),
//	)
func Measure(opts ...MeasureOption) Pipe {
	cfg := measureConfig{registry: metrics.DefaultRegistry}
	for _, opt := range opts {
		opt(&cfg)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := cfg.skip[r.URL.Path]; ok ||
				(cfg.filter != nil && !cfg.filter(r)) {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()

			holder := &routeHolder{}
			r = r.WithContext(
				context.WithValue(r.Context(), routeKey{}, holder),
			)
			incpt := &interceptor{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			defer func() {
				rec := recover()

				status := incpt.statusCode
				if rec != nil {
					// Recover further up the chain turns the panic into an
					// empty 500 response.
					status = http.StatusInternalServerError
				}

				// A mux pattern may carry a leading method ("GET /users"),
				// which the method tag already records.
				route := holder.pattern
				if route == "" {
					route = r.Pattern
				}
				route = strings.TrimPrefix(route, r.Method+" ")

				cfg.registry.Histogram(RequestDuration, nil,
					metrics.T("method", r.Method),
					metrics.T("route", route),
					metrics.T("status", strconv.Itoa(status)),
				).Observe(time.Since(start).Seconds())

				if rec != nil {
					panic(rec)
				}
			}()

			next.ServeHTTP(incpt, r)
		})
	}
}
