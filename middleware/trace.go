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
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
	"go.opentelemetry.io/otel/trace"
)

// scope is the instrumentation scope reported for spans and metrics emitted
// by this package.
const scope = "github.com/deep-rent/nexus/middleware"

// buckets are the histogram boundaries recommended by the OpenTelemetry
// semantic conventions for HTTP request durations, in seconds.
var buckets = []float64{
	0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10,
}

// routeKey is the context key under which [Trace] stores its route holder.
type routeKey struct{}

// routeHolder carries the matched route pattern by reference.
//
// [http.ServeMux] stamps the pattern onto the request it receives, but any
// middleware between [Trace] and the mux that calls [http.Request.WithContext]
// hands the mux a shallow clone, hiding the pattern from the request Trace
// holds. A pointer in the context survives every clone.
type routeHolder struct {
	pattern string
}

// SetRoute records the matched route pattern for the [Trace] middleware,
// which uses it to name the server span and to label the request duration
// metric. It is a no-op if the request is not being traced.
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

// traceConfig holds the configuration for the [Trace] middleware.
type traceConfig struct {
	tracerProvider trace.TracerProvider
	meterProvider  metric.MeterProvider
	propagator     propagation.TextMapPropagator
	filter         func(r *http.Request) bool
	skip           map[string]struct{}
}

// TraceOption configures the [Trace] middleware.
type TraceOption func(*traceConfig)

// WithTracerProvider sets the provider used to create the tracer. It defaults
// to the global provider registered with [otel.SetTracerProvider], which is a
// no-op until an application installs a real one. A nil value is ignored.
func WithTracerProvider(tp trace.TracerProvider) TraceOption {
	return func(c *traceConfig) {
		if tp != nil {
			c.tracerProvider = tp
		}
	}
}

// WithMeterProvider sets the provider used to create the request duration
// histogram. It defaults to the global provider registered with
// [otel.SetMeterProvider]. A nil value is ignored.
func WithMeterProvider(mp metric.MeterProvider) TraceOption {
	return func(c *traceConfig) {
		if mp != nil {
			c.meterProvider = mp
		}
	}
}

// WithTracePropagator sets the propagator used to extract the parent trace
// context from incoming request headers. It defaults to the global propagator
// registered with [otel.SetTextMapPropagator]. A nil value is ignored.
func WithTracePropagator(p propagation.TextMapPropagator) TraceOption {
	return func(c *traceConfig) {
		if p != nil {
			c.propagator = p
		}
	}
}

// WithTraceFilter limits tracing to requests for which keep returns true.
// Filtered requests pass through without a span or metric record. A nil
// function is ignored.
func WithTraceFilter(keep func(r *http.Request) bool) TraceOption {
	return func(c *traceConfig) {
		if keep != nil {
			c.filter = keep
		}
	}
}

// WithSkipPaths excludes requests whose URL path exactly matches one of the
// given paths from tracing. It is a convenience for high-frequency probe
// endpoints, such as the ones mounted by the health package:
//
//	middleware.Trace(middleware.WithSkipPaths(
//		"/health", "/health/live", "/health/ready",
//	))
//
// For more elaborate rules, use [WithTraceFilter].
func WithSkipPaths(paths ...string) TraceOption {
	return func(c *traceConfig) {
		if c.skip == nil {
			c.skip = make(map[string]struct{}, len(paths))
		}
		for _, p := range paths {
			c.skip[p] = struct{}{}
		}
	}
}

// Trace returns a middleware [Pipe] that instruments each HTTP request with
// OpenTelemetry.
//
// For every request it extracts the incoming trace context from the headers,
// starts a server span, and records the "http.server.request.duration"
// histogram, following the OpenTelemetry HTTP semantic conventions. The span
// is named "METHOD /route/{pattern}" when the matched route is known — either
// recorded via [SetRoute] (the router package does this) or read from
// [http.Request.Pattern] when Trace sits directly in front of the mux — and
// just "METHOD" otherwise.
//
// By default the tracer, meter, and propagator come from the otel globals,
// which are no-ops until an application registers real providers (see the
// telemetry package). The middleware is therefore safe to install
// unconditionally.
//
// A panic in a downstream handler ends the span with an error status and is
// then re-raised, so [Recover] must still sit outside Trace in the chain:
//
//	middleware.Chain(mux,
//		middleware.Recover(logger),
//		middleware.Trace(),
//		middleware.RequestID(),
//		middleware.Log(logger),
//	)
//
// This order also lets [RequestID] adopt the trace ID as the request ID.
func Trace(opts ...TraceOption) Pipe {
	cfg := traceConfig{
		tracerProvider: otel.GetTracerProvider(),
		meterProvider:  otel.GetMeterProvider(),
		propagator:     otel.GetTextMapPropagator(),
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	tracer := cfg.tracerProvider.Tracer(scope)
	duration, err := cfg.meterProvider.Meter(scope).Float64Histogram(
		"http.server.request.duration",
		metric.WithDescription("Duration of HTTP server requests."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(buckets...),
	)
	if err != nil {
		otel.Handle(err)
		duration, _ = noop.NewMeterProvider().Meter(scope).Float64Histogram("")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := cfg.skip[r.URL.Path]; ok ||
				(cfg.filter != nil && !cfg.filter(r)) {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()
			ctx := cfg.propagator.Extract(
				r.Context(), propagation.HeaderCarrier(r.Header),
			)

			holder := &routeHolder{}
			ctx = context.WithValue(ctx, routeKey{}, holder)

			ctx, span := tracer.Start(
				ctx, r.Method,
				trace.WithSpanKind(trace.SpanKindServer),
				trace.WithAttributes(requestAttrs(r)...),
			)

			r = r.WithContext(ctx)
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

				// The route becomes known only after the mux has matched.
				route := holder.pattern
				if route == "" {
					route = r.Pattern
				}
				if route != "" {
					span.SetName(spanName(r.Method, route))
					span.SetAttributes(semconv.HTTPRoute(route))
				}

				span.SetAttributes(semconv.HTTPResponseStatusCode(status))
				switch {
				case rec != nil:
					span.SetStatus(codes.Error, "panic")
				case status >= http.StatusInternalServerError:
					span.SetStatus(codes.Error, "")
				}
				span.End()

				attrs := make([]attribute.KeyValue, 0, 4)
				attrs = append(attrs,
					semconv.HTTPRequestMethodKey.String(r.Method),
					semconv.HTTPResponseStatusCode(status),
					semconv.URLScheme(scheme(r)),
				)
				if route != "" {
					attrs = append(attrs, semconv.HTTPRoute(route))
				}
				duration.Record(ctx, time.Since(start).Seconds(),
					metric.WithAttributes(attrs...))

				if rec != nil {
					panic(rec)
				}
			}()

			next.ServeHTTP(incpt, r)
		})
	}
}

// spanName renders the low-cardinality span name "METHOD route". A
// [http.ServeMux] pattern may already carry a leading method ("GET /users"),
// which is not repeated.
func spanName(method, route string) string {
	if strings.HasPrefix(route, method+" ") {
		return route
	}
	return method + " " + route
}

// requestAttrs assembles the semantic convention attributes known at the
// start of a request.
func requestAttrs(r *http.Request) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, 8)
	attrs = append(attrs,
		semconv.HTTPRequestMethodKey.String(r.Method),
		semconv.URLPath(r.URL.Path),
		semconv.URLScheme(scheme(r)),
		semconv.NetworkProtocolVersion(
			strings.TrimPrefix(r.Proto, "HTTP/"),
		),
	)
	if host, port, err := net.SplitHostPort(r.Host); err == nil {
		attrs = append(attrs, semconv.ServerAddress(host))
		if n, err := strconv.Atoi(port); err == nil {
			attrs = append(attrs, semconv.ServerPort(n))
		}
	} else if r.Host != "" {
		attrs = append(attrs, semconv.ServerAddress(r.Host))
	}
	if ua := r.UserAgent(); ua != "" {
		attrs = append(attrs, semconv.UserAgentOriginal(ua))
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		attrs = append(attrs, semconv.ClientAddress(host))
	}
	return attrs
}

// scheme reports the URL scheme of a request as seen by this server.
func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}
