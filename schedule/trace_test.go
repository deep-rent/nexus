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

package schedule_test

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/codes"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/deep-rent/nexus/log"
	"github.com/deep-rent/nexus/schedule"
)

func TestRun_RecordsSpan(t *testing.T) {
	t.Parallel()

	spans := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	s := schedule.New(t.Context(), schedule.WithTracerProvider(tp))

	ran := make(chan struct{})
	s.Dispatch(schedule.Named("refresh", schedule.TickFn(
		func(context.Context) time.Duration {
			close(ran)
			return time.Hour
		},
	)))

	select {
	case <-ran:
	case <-time.After(5 * time.Second):
		t.Fatal("tick did not run")
	}
	s.Shutdown()

	ended := spans.Ended()
	if len(ended) != 1 {
		t.Fatalf("spans: got %d; want 1", len(ended))
	}
	span := ended[0]

	if got, want := span.Name(), "refresh"; got != want {
		t.Errorf("name: got %q; want %q", got, want)
	}
	if got := span.SpanKind(); got != trace.SpanKindInternal {
		t.Errorf("kind: got %v; want %v", got, trace.SpanKindInternal)
	}

	// Each run is its own root trace.
	if got := span.Parent(); got.IsValid() {
		t.Errorf("parent: got %v; want none", got)
	}
}

func TestRun_RecordsPanic(t *testing.T) {
	t.Parallel()

	spans := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	s := schedule.New(t.Context(),
		schedule.WithLogger(log.Silent()),
		schedule.WithTracerProvider(tp),
		schedule.WithMeterProvider(mp),
	)

	ran := make(chan struct{})
	s.Dispatch(schedule.Named("broken", schedule.TickFn(
		func(context.Context) time.Duration {
			close(ran)
			panic("boom")
		},
	)))

	select {
	case <-ran:
	case <-time.After(5 * time.Second):
		t.Fatal("tick did not run")
	}
	s.Shutdown()

	ended := spans.Ended()
	if len(ended) != 1 {
		t.Fatalf("spans: got %d; want 1", len(ended))
	}
	if got := ended[0].Status().Code; got != codes.Error {
		t.Errorf("status: got %v; want %v", got, codes.Error)
	}

	// The panic counter carries the tick name.
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &rm); err != nil {
		t.Fatalf("collecting metrics: %v", err)
	}

	var count int64
	var tick string
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != "nexus.schedule.tick.panic" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("unexpected data type %T", m.Data)
			}
			for _, dp := range sum.DataPoints {
				count += dp.Value
				if v, ok := dp.Attributes.Value("tick"); ok {
					tick = v.Emit()
				}
			}
		}
	}
	if count != 1 {
		t.Errorf("panic count: got %d; want 1", count)
	}
	if tick != "broken" {
		t.Errorf("tick attribute: got %q; want %q", tick, "broken")
	}
}
