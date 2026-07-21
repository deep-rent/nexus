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

package telemetry

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel/trace"
)

// Attribute keys under which [NewLogHandler] records the trace context.
// They are exported so that log processors can find the values by a stable
// name.
const (
	// TraceIDKey is the key under which the trace ID is recorded.
	TraceIDKey = "trace_id"
	// SpanIDKey is the key under which the span ID is recorded.
	SpanIDKey = "span_id"
)

// logHandler decorates an [slog.Handler] with trace correlation.
type logHandler struct {
	next slog.Handler
}

// NewLogHandler wraps a handler so that every record logged with a context
// carrying an active span is annotated with the trace and span IDs under
// [TraceIDKey] and [SpanIDKey]. Records logged outside a trace pass through
// unchanged.
//
// Compose it with the log package's constructor:
//
//	logger := slog.New(telemetry.NewLogHandler(log.NewHandler(
//		log.WithFormat(log.FormatJSON),
//	)))
//
// This is what ties the three signals together: a log line found by its
// trace_id leads to the full trace, and vice versa.
//
// Note that when a logger has an open group (via [slog.Logger.WithGroup]),
// the injected attributes land inside that group; loggers assembled once at
// startup are unaffected.
func NewLogHandler(next slog.Handler) slog.Handler {
	return &logHandler{next: next}
}

// Enabled delegates to the wrapped handler.
func (h *logHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

// Handle annotates the record with the active trace context, if any, before
// delegating to the wrapped handler.
func (h *logHandler) Handle(ctx context.Context, rec slog.Record) error {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		rec.AddAttrs(
			slog.String(TraceIDKey, sc.TraceID().String()),
			slog.String(SpanIDKey, sc.SpanID().String()),
		)
	}
	return h.next.Handle(ctx, rec)
}

// WithAttrs delegates to the wrapped handler, preserving the decoration.
func (h *logHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &logHandler{next: h.next.WithAttrs(attrs)}
}

// WithGroup delegates to the wrapped handler, preserving the decoration.
func (h *logHandler) WithGroup(name string) slog.Handler {
	return &logHandler{next: h.next.WithGroup(name)}
}

var _ slog.Handler = (*logHandler)(nil)
