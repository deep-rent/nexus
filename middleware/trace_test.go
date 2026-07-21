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

package middleware_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	mw "github.com/deep-rent/nexus/middleware"
)

// tracing bundles a recording tracer provider, a manual metric reader, and
// the Trace options wiring them up.
type tracing struct {
	spans  *tracetest.SpanRecorder
	reader *sdkmetric.ManualReader
	opts   []mw.TraceOption
}

func newTracing(t *testing.T) *tracing {
	t.Helper()

	spans := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	return &tracing{
		spans:  spans,
		reader: reader,
		opts: []mw.TraceOption{
			mw.WithTracerProvider(tp),
			mw.WithMeterProvider(mp),
			mw.WithTracePropagator(propagation.TraceContext{}),
		},
	}
}

// attrValue returns the string form of an attribute recorded on a span, or
// the empty string if the key is absent.
func attrValue(s sdktrace.ReadOnlySpan, key attribute.Key) string {
	for _, kv := range s.Attributes() {
		if kv.Key == key {
			return kv.Value.Emit()
		}
	}
	return ""
}

// histogramCount returns the number of samples recorded for the HTTP server
// duration histogram.
func histogramCount(t *testing.T, reader *sdkmetric.ManualReader) uint64 {
	t.Helper()

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &rm); err != nil {
		t.Fatalf("collecting metrics: %v", err)
	}

	var count uint64
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != "http.server.request.duration" {
				continue
			}
			hist, ok := m.Data.(metricdata.Histogram[float64])
			if !ok {
				t.Fatalf("unexpected data type %T", m.Data)
			}
			for _, dp := range hist.DataPoints {
				count += dp.Count
			}
		}
	}
	return count
}

func TestTrace_RecordsServerSpan(t *testing.T) {
	t.Parallel()

	tr := newTracing(t)
	h := mw.Chain(mockHandler, mw.Trace(tr.opts...))

	req := httptest.NewRequest(http.MethodGet, "/users/42", nil)
	req.Header.Set("User-Agent", "test-agent")
	req.Header.Set(
		"traceparent",
		"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
	)

	h.ServeHTTP(httptest.NewRecorder(), req)

	spans := tr.spans.Ended()
	if len(spans) != 1 {
		t.Fatalf("spans: got %d; want 1", len(spans))
	}
	span := spans[0]

	if got := span.SpanKind(); got != trace.SpanKindServer {
		t.Errorf("kind: got %v; want %v", got, trace.SpanKindServer)
	}

	// Without a matched route, the span is named after the method alone.
	if got := span.Name(); got != http.MethodGet {
		t.Errorf("name: got %q; want %q", got, http.MethodGet)
	}

	// The inbound traceparent supplies the parent span context.
	want := "0af7651916cd43dd8448eb211c80319c"
	if got := span.SpanContext().TraceID().String(); got != want {
		t.Errorf("trace id: got %q; want %q", got, want)
	}
	if got := span.Parent().SpanID().String(); got != "b7ad6b7169203331" {
		t.Errorf("parent span id: got %q", got)
	}

	if got := attrValue(span, "url.path"); got != "/users/42" {
		t.Errorf("url.path: got %q; want %q", got, "/users/42")
	}
	if got := attrValue(span, "http.response.status_code"); got != "200" {
		t.Errorf("status attr: got %q; want %q", got, "200")
	}
	if got := attrValue(span, "user_agent.original"); got != "test-agent" {
		t.Errorf("user agent: got %q; want %q", got, "test-agent")
	}

	if got := histogramCount(t, tr.reader); got != 1 {
		t.Errorf("histogram count: got %d; want 1", got)
	}
}

func TestTrace_NamesSpanAfterRoute(t *testing.T) {
	t.Parallel()

	t.Run("via SetRoute", func(t *testing.T) {
		t.Parallel()

		tr := newTracing(t)
		h := mw.Chain(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mw.SetRoute(r.Context(), "/users/{id}")
				w.WriteHeader(http.StatusOK)
			}),
			mw.Trace(tr.opts...),
		)

		h.ServeHTTP(
			httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, "/users/42", nil),
		)

		spans := tr.spans.Ended()
		if len(spans) != 1 {
			t.Fatalf("spans: got %d; want 1", len(spans))
		}
		if got, want := spans[0].Name(), "GET /users/{id}"; got != want {
			t.Errorf("name: got %q; want %q", got, want)
		}
		if got := attrValue(spans[0], "http.route"); got != "/users/{id}" {
			t.Errorf("http.route: got %q; want %q", got, "/users/{id}")
		}
	})

	t.Run("via mux pattern", func(t *testing.T) {
		t.Parallel()

		mux := http.NewServeMux()
		mux.Handle("GET /users/{id}", mockHandler)

		tr := newTracing(t)
		h := mw.Chain(mux, mw.Trace(tr.opts...))

		h.ServeHTTP(
			httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, "/users/42", nil),
		)

		spans := tr.spans.Ended()
		if len(spans) != 1 {
			t.Fatalf("spans: got %d; want 1", len(spans))
		}
		if got, want := spans[0].Name(), "GET /users/{id}"; got != want {
			t.Errorf("name: got %q; want %q", got, want)
		}
	})
}

func TestTrace_SkipsExcludedRequests(t *testing.T) {
	t.Parallel()

	t.Run("skip paths", func(t *testing.T) {
		t.Parallel()

		tr := newTracing(t)
		h := mw.Chain(
			mockHandler,
			mw.Trace(append(tr.opts, mw.WithSkipPaths("/health"))...),
		)

		h.ServeHTTP(
			httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, "/health", nil),
		)

		if got := len(tr.spans.Ended()); got != 0 {
			t.Errorf("spans: got %d; want 0", got)
		}
		if got := histogramCount(t, tr.reader); got != 0 {
			t.Errorf("histogram count: got %d; want 0", got)
		}
	})

	t.Run("filter", func(t *testing.T) {
		t.Parallel()

		tr := newTracing(t)
		keep := func(r *http.Request) bool { return r.Method != http.MethodGet }
		h := mw.Chain(
			mockHandler,
			mw.Trace(append(tr.opts, mw.WithTraceFilter(keep))...),
		)

		h.ServeHTTP(
			httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, "/", nil),
		)

		if got := len(tr.spans.Ended()); got != 0 {
			t.Errorf("spans: got %d; want 0", got)
		}
	})
}

func TestTrace_MarksServerErrors(t *testing.T) {
	t.Parallel()

	tr := newTracing(t)
	h := mw.Chain(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}),
		mw.Trace(tr.opts...),
	)

	h.ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/", nil),
	)

	spans := tr.spans.Ended()
	if len(spans) != 1 {
		t.Fatalf("spans: got %d; want 1", len(spans))
	}
	if got := spans[0].Status().Code; got != codes.Error {
		t.Errorf("status: got %v; want %v", got, codes.Error)
	}
	if got := attrValue(spans[0], "http.response.status_code"); got != "502" {
		t.Errorf("status attr: got %q; want %q", got, "502")
	}
}

func TestTrace_EndsSpanOnPanic(t *testing.T) {
	t.Parallel()

	tr := newTracing(t)
	h := mw.Chain(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic("boom")
		}),
		mw.Recover(mockLogger(&bytes.Buffer{})),
		mw.Trace(tr.opts...),
	)

	res := httptest.NewRecorder()
	h.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/", nil))

	// Recover outside Trace still converts the re-raised panic into a 500.
	if got := res.Code; got != http.StatusInternalServerError {
		t.Errorf(
			"response: got %d; want %d",
			got,
			http.StatusInternalServerError,
		)
	}

	spans := tr.spans.Ended()
	if len(spans) != 1 {
		t.Fatalf("spans: got %d; want 1", len(spans))
	}
	if got := spans[0].Status().Code; got != codes.Error {
		t.Errorf("status: got %v; want %v", got, codes.Error)
	}
	if got := attrValue(spans[0], "http.response.status_code"); got != "500" {
		t.Errorf("status attr: got %q; want %q", got, "500")
	}
}

func TestRequestID_AdoptsTraceID(t *testing.T) {
	t.Parallel()

	tr := newTracing(t)
	h := mw.Chain(mockHandler, mw.Trace(tr.opts...), mw.RequestID())

	res := httptest.NewRecorder()
	h.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/", nil))

	spans := tr.spans.Ended()
	if len(spans) != 1 {
		t.Fatalf("spans: got %d; want 1", len(spans))
	}

	want := spans[0].SpanContext().TraceID().String()
	if got := res.Header().Get("X-Request-ID"); got != want {
		t.Errorf("request id: got %q; want %q", got, want)
	}
}
