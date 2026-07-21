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

package telemetry_test

import (
	"context"
	"sync"
	"testing"

	"github.com/deep-rent/nexus/telemetry"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// captureExporter is a span exporter that retains everything it receives,
// even across shutdown. The SDK's own tracetest.InMemoryExporter resets its
// storage on shutdown, which is exactly the moment these tests inspect.
type captureExporter struct {
	mu    sync.Mutex
	spans tracetest.SpanStubs
}

func (e *captureExporter) ExportSpans(
	_ context.Context,
	spans []sdktrace.ReadOnlySpan,
) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.spans = append(e.spans, tracetest.SpanStubsFromReadOnlySpans(spans)...)
	return nil
}

func (e *captureExporter) Shutdown(context.Context) error { return nil }

func (e *captureExporter) GetSpans() tracetest.SpanStubs {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.spans
}

var _ sdktrace.SpanExporter = (*captureExporter)(nil)

// newTelemetry builds a Telemetry against in-memory exporters, so that no
// test ever dials a collector.
func newTelemetry(
	t *testing.T,
	opts ...telemetry.Option,
) (*telemetry.Telemetry, *captureExporter, *sdkmetric.ManualReader) {
	t.Helper()

	spans := &captureExporter{}
	reader := sdkmetric.NewManualReader()

	tel, err := telemetry.New(t.Context(), append(opts,
		telemetry.WithServiceName("test"),
		telemetry.WithSpanExporter(spans),
		telemetry.WithMetricReader(reader),
	)...)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	t.Cleanup(func() { _ = tel.Shutdown(context.Background()) })

	return tel, spans, reader
}

func TestNew_RegistersGlobalProviders(t *testing.T) {
	tel, spans, reader := newTelemetry(t)

	if got := otel.GetTracerProvider(); got != tel.TracerProvider() {
		t.Error("global tracer provider was not registered")
	}
	if got := otel.GetMeterProvider(); got != tel.MeterProvider() {
		t.Error("global meter provider was not registered")
	}

	// A span emitted through the global provider reaches the exporter after
	// shutdown flushes the batch processor.
	_, span := otel.Tracer("test").Start(t.Context(), "op")
	span.End()

	counter, err := otel.Meter("test").Int64Counter("test.count")
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	counter.Add(t.Context(), 1)

	// Metrics are collected before the shutdown below stops the reader.
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collecting metrics: %v", err)
	}
	if len(rm.ScopeMetrics) == 0 {
		t.Error("metrics: got none; want the recorded counter")
	}

	if err := tel.Shutdown(context.Background()); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	got := spans.GetSpans()
	if len(got) != 1 {
		t.Fatalf("spans: got %d; want 1", len(got))
	}
	if got[0].Name != "op" {
		t.Errorf("name: got %q; want %q", got[0].Name, "op")
	}

	// The service name lands on the exported resource.
	var found bool
	for _, kv := range got[0].Resource.Attributes() {
		if kv.Key == "service.name" && kv.Value.Emit() == "test" {
			found = true
		}
	}
	if !found {
		t.Error("service.name resource attribute not found")
	}
}

func TestNew_Disabled(t *testing.T) {
	tests := []struct {
		name string
		opts []telemetry.Option
		env  string
	}{
		{name: "via option", opts: []telemetry.Option{
			telemetry.WithDisabled(true),
		}},
		{name: "via environment", env: "true"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env != "" {
				t.Setenv("OTEL_SDK_DISABLED", tt.env)
			}

			tel, err := telemetry.New(t.Context(), tt.opts...)
			if err != nil {
				t.Fatalf("should not have returned an error: %v", err)
			}

			// The providers are no-ops: spans never record.
			_, span := tel.TracerProvider().Tracer("test").
				Start(t.Context(), "op")
			if span.IsRecording() {
				t.Error("span is recording; want no-op")
			}
			span.End()

			if err := tel.Shutdown(context.Background()); err != nil {
				t.Errorf("shutdown: should not have returned an error: %v", err)
			}
		})
	}
}

func TestNew_ServiceNameFromEnvironment(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "from-env")

	spans := &captureExporter{}
	tel, err := telemetry.New(t.Context(),
		telemetry.WithServiceName("from-option"),
		telemetry.WithSpanExporter(spans),
		telemetry.WithMetricReader(sdkmetric.NewManualReader()),
	)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	_, span := tel.TracerProvider().Tracer("test").Start(t.Context(), "op")
	span.End()

	if err := tel.Shutdown(context.Background()); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	got := spans.GetSpans()
	if len(got) != 1 {
		t.Fatalf("spans: got %d; want 1", len(got))
	}

	// The environment variable outranks the option.
	for _, kv := range got[0].Resource.Attributes() {
		if kv.Key == "service.name" && kv.Value.Emit() != "from-env" {
			t.Errorf(
				"service.name: got %q; want %q",
				kv.Value.Emit(), "from-env",
			)
		}
	}
}
