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

package transport_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/deep-rent/nexus/retry"
	"github.com/deep-rent/nexus/transport"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// clientTracing bundles a recording tracer provider, a manual metric reader,
// and the trace options wiring them up.
type clientTracing struct {
	spans  *tracetest.SpanRecorder
	reader *sdkmetric.ManualReader
	opts   []transport.TraceOption
}

func newClientTracing(t *testing.T) *clientTracing {
	t.Helper()

	spans := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	return &clientTracing{
		spans:  spans,
		reader: reader,
		opts: []transport.TraceOption{
			transport.WithTracerProvider(tp),
			transport.WithMeterProvider(mp),
			transport.WithTracePropagator(propagation.TraceContext{}),
		},
	}
}

// clientAttr returns the string form of an attribute recorded on a span, or
// the empty string if the key is absent.
func clientAttr(s sdktrace.ReadOnlySpan, key attribute.Key) string {
	for _, kv := range s.Attributes() {
		if kv.Key == key {
			return kv.Value.Emit()
		}
	}
	return ""
}

func TestTrace_RecordsClientSpan(t *testing.T) {
	t.Parallel()

	var traceparent string
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			traceparent = r.Header.Get("traceparent")
			w.WriteHeader(http.StatusOK)
		},
	))
	defer srv.Close()

	tr := newClientTracing(t)
	client := &http.Client{
		Transport: transport.New(transport.WithTrace(tr.opts...)),
	}

	res, err := client.Get(srv.URL + "/things")
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	res.Body.Close()

	spans := tr.spans.Ended()
	if len(spans) != 1 {
		t.Fatalf("spans: got %d; want 1", len(spans))
	}
	span := spans[0]

	if got := span.SpanKind(); got != trace.SpanKindClient {
		t.Errorf("kind: got %v; want %v", got, trace.SpanKindClient)
	}
	if got := span.Name(); got != http.MethodGet {
		t.Errorf("name: got %q; want %q", got, http.MethodGet)
	}
	if got, want := clientAttr(span, "url.full"), srv.URL+"/things"; got != want {
		t.Errorf("url.full: got %q; want %q", got, want)
	}
	if got := clientAttr(span, "http.response.status_code"); got != "200" {
		t.Errorf("status attr: got %q; want %q", got, "200")
	}

	// The trace context reaches the server, carrying the span's trace ID.
	want := span.SpanContext().TraceID().String()
	if !strings.Contains(traceparent, want) {
		t.Errorf("traceparent: got %q; want trace ID %q", traceparent, want)
	}

	// One sample lands in the client duration histogram.
	var rm metricdata.ResourceMetrics
	if err := tr.reader.Collect(t.Context(), &rm); err != nil {
		t.Fatalf("collecting metrics: %v", err)
	}
	var count uint64
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != "http.client.request.duration" {
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
	if count != 1 {
		t.Errorf("histogram count: got %d; want 1", count)
	}
}

func TestTrace_RecordsEachRetryAttempt(t *testing.T) {
	t.Parallel()

	var traceparents []string
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			traceparents = append(traceparents, r.Header.Get("traceparent"))
			w.WriteHeader(http.StatusServiceUnavailable)
		},
	))
	defer srv.Close()

	tr := newClientTracing(t)
	client := &http.Client{
		Transport: transport.New(
			transport.WithTrace(tr.opts...),
			transport.WithRetry(retry.WithAttemptLimit(3)),
		),
	}

	res, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	res.Body.Close()

	// Every attempt is recorded as its own failed client span.
	spans := tr.spans.Ended()
	if len(spans) != 3 {
		t.Fatalf("spans: got %d; want 3", len(spans))
	}
	for i, span := range spans {
		if got := span.Status().Code; got != codes.Error {
			t.Errorf("span %d status: got %v; want %v", i, got, codes.Error)
		}
	}

	// Attempts after the first carry the resend count.
	if got := clientAttr(spans[0], "http.request.resend_count"); got != "" {
		t.Errorf("first attempt resend count: got %q; want none", got)
	}
	if got := clientAttr(spans[1], "http.request.resend_count"); got != "1" {
		t.Errorf("second attempt resend count: got %q; want %q", got, "1")
	}
	if got := clientAttr(spans[2], "http.request.resend_count"); got != "2" {
		t.Errorf("third attempt resend count: got %q; want %q", got, "2")
	}

	// Each attempt injects its own span context into the wire headers.
	if len(traceparents) != 3 {
		t.Fatalf("traceparents: got %d; want 3", len(traceparents))
	}
	for i, span := range spans {
		want := span.SpanContext().SpanID().String()
		if !strings.Contains(traceparents[i], want) {
			t.Errorf(
				"attempt %d traceparent: got %q; want span ID %q",
				i, traceparents[i], want,
			)
		}
	}
}

func TestTrace_RecordsTransportErrors(t *testing.T) {
	t.Parallel()

	tr := newClientTracing(t)
	client := &http.Client{
		Transport: transport.New(transport.WithTrace(tr.opts...)),
	}

	// The address is unroutable, so the dial fails.
	res, err := client.Get("http://127.0.0.1:1")
	if err == nil {
		res.Body.Close()
		t.Fatal("should have returned an error")
	}

	spans := tr.spans.Ended()
	if len(spans) != 1 {
		t.Fatalf("spans: got %d; want 1", len(spans))
	}
	if got := spans[0].Status().Code; got != codes.Error {
		t.Errorf("status: got %v; want %v", got, codes.Error)
	}
	if len(spans[0].Events()) == 0 {
		t.Error("events: got none; want a recorded exception")
	}
}
