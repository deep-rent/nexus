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
	"bytes"
	"context"
	"encoding/json/v2"
	"log/slog"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/deep-rent/nexus/telemetry"
)

func TestLogHandler(t *testing.T) {
	t.Parallel()

	create := func(buf *bytes.Buffer) *slog.Logger {
		return slog.New(telemetry.Wrap(
			slog.NewJSONHandler(buf, nil),
		))
	}

	decode := func(t *testing.T, buf *bytes.Buffer) map[string]any {
		t.Helper()
		var rec map[string]any
		if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
			t.Fatalf("decoding record: %v", err)
		}
		return rec
	}

	t.Run("injects trace context", func(t *testing.T) {
		t.Parallel()

		tp := sdktrace.NewTracerProvider()
		t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

		ctx, span := tp.Tracer("test").Start(t.Context(), "op")
		defer span.End()

		var buf bytes.Buffer
		create(&buf).InfoContext(ctx, "hello")

		rec := decode(t, &buf)
		sc := span.SpanContext()
		if got := rec[telemetry.TraceIDKey]; got != sc.TraceID().String() {
			t.Errorf("trace_id: got %v; want %q", got, sc.TraceID())
		}
		if got := rec[telemetry.SpanIDKey]; got != sc.SpanID().String() {
			t.Errorf("span_id: got %v; want %q", got, sc.SpanID())
		}
	})

	t.Run("passes untraced records through", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		create(&buf).InfoContext(t.Context(), "hello")

		rec := decode(t, &buf)
		if _, ok := rec[telemetry.TraceIDKey]; ok {
			t.Error("trace_id present; want absent")
		}
		if got := rec["msg"]; got != "hello" {
			t.Errorf("msg: got %v; want %q", got, "hello")
		}
	})

	t.Run("preserves decoration through WithAttrs and WithGroup", func(
		t *testing.T,
	) {
		t.Parallel()

		tp := sdktrace.NewTracerProvider()
		t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

		ctx, span := tp.Tracer("test").Start(t.Context(), "op")
		defer span.End()

		var buf bytes.Buffer
		create(&buf).With(slog.String("k", "v")).InfoContext(ctx, "hello")

		rec := decode(t, &buf)
		if _, ok := rec[telemetry.TraceIDKey]; !ok {
			t.Error("trace_id absent after WithAttrs; want present")
		}
		if got := rec["k"]; got != "v" {
			t.Errorf("k: got %v; want %q", got, "v")
		}
	})
}
