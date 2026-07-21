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

package transport

import (
	"fmt"
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

	"github.com/deep-rent/nexus/retry"
)

// scope is the instrumentation scope reported for spans and metrics emitted
// by this package.
const scope = "github.com/deep-rent/nexus/transport"

// buckets are the histogram boundaries recommended by the OpenTelemetry
// semantic conventions for HTTP request durations, in seconds.
var buckets = []float64{
	0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10,
}

// traceConfig holds the configuration for a tracing transport.
type traceConfig struct {
	tracerProvider trace.TracerProvider
	meterProvider  metric.MeterProvider
	propagator     propagation.TextMapPropagator
}

// TraceOption configures a tracing transport created by [NewTraceTransport]
// or enabled via [WithTrace].
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

// WithTracePropagator sets the propagator used to inject the trace context
// into outgoing request headers. It defaults to the global propagator
// registered with [otel.SetTextMapPropagator]. A nil value is ignored.
func WithTracePropagator(p propagation.TextMapPropagator) TraceOption {
	return func(c *traceConfig) {
		if p != nil {
			c.propagator = p
		}
	}
}

// traceTransport wraps an underlying [http.RoundTripper] with OpenTelemetry
// client instrumentation.
type traceTransport struct {
	next       http.RoundTripper
	tracer     trace.Tracer
	propagator propagation.TextMapPropagator
	duration   metric.Float64Histogram
}

// NewTraceTransport wraps a transport with OpenTelemetry client
// instrumentation.
//
// Every round trip is recorded as a client span carrying the HTTP semantic
// convention attributes and measured in the "http.client.request.duration"
// histogram. The trace context is injected into the outgoing headers, so a
// downstream service instrumented with the middleware package continues the
// same trace.
//
// When layered below a [retry.NewTransport] — the placement chosen by
// [WithTrace] — each retry attempt is recorded as its own span with a fresh
// header injection, and attempts after the first carry the
// "http.request.resend_count" attribute.
func NewTraceTransport(
	next http.RoundTripper,
	opts ...TraceOption,
) http.RoundTripper {
	cfg := traceConfig{
		tracerProvider: otel.GetTracerProvider(),
		meterProvider:  otel.GetMeterProvider(),
		propagator:     otel.GetTextMapPropagator(),
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	duration, err := cfg.meterProvider.Meter(scope).Float64Histogram(
		"http.client.request.duration",
		metric.WithDescription("Duration of HTTP client requests."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(buckets...),
	)
	if err != nil {
		otel.Handle(err)
		duration, _ = noop.NewMeterProvider().Meter(scope).Float64Histogram("")
	}

	return &traceTransport{
		next:       next,
		tracer:     cfg.tracerProvider.Tracer(scope),
		propagator: cfg.propagator,
		duration:   duration,
	}
}

// RoundTrip executes a single HTTP transaction inside a client span. The
// caller's request is never modified: the span context and trace headers are
// carried by a clone, as required by the [http.RoundTripper] contract.
func (t *traceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	attrs := make([]attribute.KeyValue, 0, 6)
	attrs = append(attrs,
		semconv.HTTPRequestMethodKey.String(req.Method),
		// Redacted strips the password from any userinfo in the URL.
		semconv.URLFull(req.URL.Redacted()),
		semconv.ServerAddress(req.URL.Hostname()),
	)
	if port, err := strconv.Atoi(req.URL.Port()); err == nil {
		attrs = append(attrs, semconv.ServerPort(port))
	}
	if count := retry.AttemptCount(req.Context()); count > 1 {
		attrs = append(attrs, semconv.HTTPRequestResendCount(count-1))
	}

	start := time.Now()
	ctx, span := t.tracer.Start(
		req.Context(), req.Method,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attrs...),
	)

	req = req.Clone(ctx)
	t.propagator.Inject(ctx, propagation.HeaderCarrier(req.Header))

	res, err := t.next.RoundTrip(req)

	mattrs := make([]attribute.KeyValue, 0, 4)
	mattrs = append(mattrs,
		semconv.HTTPRequestMethodKey.String(req.Method),
		semconv.ServerAddress(req.URL.Hostname()),
	)

	switch {
	case err != nil:
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		mattrs = append(mattrs, errorType(err))
	default:
		span.SetAttributes(
			semconv.HTTPResponseStatusCode(res.StatusCode),
			semconv.NetworkProtocolVersion(
				strings.TrimPrefix(res.Proto, "HTTP/"),
			),
		)
		// For a client, any 4xx or 5xx response marks a failed span.
		if res.StatusCode >= http.StatusBadRequest {
			span.SetStatus(codes.Error, "")
		}
		mattrs = append(mattrs,
			semconv.HTTPResponseStatusCode(res.StatusCode),
		)
	}
	span.End()

	t.duration.Record(ctx, time.Since(start).Seconds(),
		metric.WithAttributes(mattrs...))

	return res, err
}

// errorType renders the "error.type" attribute for a transport error.
func errorType(err error) attribute.KeyValue {
	return semconv.ErrorTypeKey.String(fmt.Sprintf("%T", err))
}

var _ http.RoundTripper = (*traceTransport)(nil)
