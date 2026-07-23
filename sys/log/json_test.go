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

package log_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/deep-rent/nexus/sys/log"
)

// traceable is a fake error carrying an occurrence identifier.
type traceable struct {
	msg string
	id  string
}

func (e *traceable) Error() string   { return e.msg }
func (e *traceable) ErrorID() string { return e.id }

// record unmarshals the single JSON line captured in buf, failing the
// test on malformed output or an unexpected record count.
func record(t *testing.T, buf *log.Buffer) map[string]any {
	t.Helper()
	lines := buf.Lines()
	if len(lines) != 1 {
		t.Fatalf("got %d records; want 1: %q", len(lines), buf.String())
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatalf("malformed JSON %q: %v", lines[0], err)
	}
	return m
}

func TestSink_Record(t *testing.T) {
	t.Parallel()

	logger, buf := log.Capture()
	logger.Info(t.Context(), "Server started", log.Int("port", 8080))

	m := record(t, buf)
	if got, want := m["level"], "info"; got != want {
		t.Errorf("got level %v; want %v", got, want)
	}
	if got, want := m["msg"], "Server started"; got != want {
		t.Errorf("got msg %v; want %v", got, want)
	}
	if got, want := m["port"], float64(8080); got != want {
		t.Errorf("got port %v; want %v", got, want)
	}

	// The timestamp must parse as RFC 3339 and be expressed in UTC.
	ts, ok := m["time"].(string)
	if !ok {
		t.Fatalf("missing time in %v", m)
	}
	parsed, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		t.Fatalf("malformed timestamp %q: %v", ts, err)
	}
	if _, offset := parsed.Zone(); offset != 0 {
		t.Errorf("timestamp %q is not UTC", ts)
	}
	if d := time.Since(parsed); d < 0 || d > time.Minute {
		t.Errorf("timestamp %q is not recent", ts)
	}

	// The root logger has no path, so the key must be absent entirely.
	if _, ok := m["logger"]; ok {
		t.Errorf("root logger should not emit a logger key: %v", m)
	}
}

func TestSink_Kinds(t *testing.T) {
	t.Parallel()

	instant := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC)

	tests := []struct {
		name string
		in   log.Arg
		want any
	}{
		{"string", log.String("k", "v"), "v"},
		{"int", log.Int("k", -42), float64(-42)},
		{"int8", log.Int8("k", -8), float64(-8)},
		{"int16", log.Int16("k", -16), float64(-16)},
		{"int32", log.Int32("k", -32), float64(-32)},
		{"int64", log.Int64("k", 1<<40), float64(1 << 40)},
		{"uint", log.Uint("k", 42), float64(42)},
		{"uint8", log.Uint8("k", 8), float64(8)},
		{"uint16", log.Uint16("k", 16), float64(16)},
		{"uint32", log.Uint32("k", 32), float64(32)},
		{"uint64", log.Uint64("k", 7), float64(7)},
		// A float32 must keep its shortest 32-bit representation instead
		// of the noisy float64 conversion (3.0999999046325684).
		{"float32", log.Float32("k", 3.1), 3.1},
		{"float64", log.Float64("k", 3.25), 3.25},
		{"bool", log.Bool("k", true), true},
		{"duration", log.Duration("k", 1500*time.Millisecond), 1.5},
		{"time", log.Time("k", instant), "2026-01-02T03:04:05.123456789Z"},
		{
			name: "uuid",
			in: log.UUID("k", uuid.MustParse(
				"0195c2a7-9e4b-7c58-8000-0123456789ab",
			)),
			want: "0195c2a7-9e4b-7c58-8000-0123456789ab",
		},
		{"error", log.Err(errors.New("boom")), "boom"},
		{"nil error", log.Err(nil), nil},
		{"nan", log.Float64("k", math.NaN()), "NaN"},
		{"+inf", log.Float64("k", math.Inf(+1)), "+Inf"},
		{"-inf", log.Float64("k", math.Inf(-1)), "-Inf"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			logger, buf := log.Capture()
			logger.Info(t.Context(), "m", tt.in)
			if got := record(t, buf)[tt.in.Key]; got != tt.want {
				t.Errorf("got %v (%T); want %v (%T)",
					got, got, tt.want, tt.want)
			}
		})
	}
}

func TestSink_Traceable(t *testing.T) {
	t.Parallel()

	terr := &traceable{msg: "boom", id: "0195c2a7-9e4b-7c58"}

	tests := []struct {
		name   string
		in     error
		wantID any // nil means the key must be absent
	}{
		{"direct", terr, "0195c2a7-9e4b-7c58"},
		// The identifier must be found through wrapping and joining.
		{"wrapped", fmt.Errorf("handling: %w", terr), "0195c2a7-9e4b-7c58"},
		{
			name:   "joined",
			in:     errors.Join(errors.New("other"), terr),
			wantID: "0195c2a7-9e4b-7c58",
		},
		{"plain", errors.New("boom"), nil},
		// An empty identifier carries no information and is dropped.
		{"empty id", &traceable{msg: "boom"}, nil},
		{"nil", nil, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			logger, buf := log.Capture()
			logger.Error(t.Context(), "failed", log.Err(tt.in))

			m := record(t, buf)
			got, ok := m[log.ErrorIDKey]
			if tt.wantID == nil {
				if ok {
					t.Errorf("unexpected %s %v", log.ErrorIDKey, got)
				}
				return
			}
			if got != tt.wantID {
				t.Errorf("got %s %v; want %v", log.ErrorIDKey, got,
					tt.wantID)
			}
		})
	}
}

// Times attached in a non-UTC zone must be normalized to UTC on output.
func TestSink_TimeZone(t *testing.T) {
	t.Parallel()

	zone := time.FixedZone("UTC+2", 2*60*60)
	instant := time.Date(2026, 1, 2, 5, 4, 5, 0, zone)

	logger, buf := log.Capture()
	logger.Info(t.Context(), "m", log.Time("t", instant))

	if got, want := record(t, buf)["t"], "2026-01-02T03:04:05Z"; got != want {
		t.Errorf("got %v; want %v", got, want)
	}
}

func TestSink_Escaping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"quote", `say "hi"`, `say "hi"`},
		{"backslash", `C:\path`, `C:\path`},
		{"newline", "a\nb", "a\nb"},
		{"tab", "a\tb", "a\tb"},
		{"control", "a\x01b", "a\x01b"},
		{"unicode", "héllo wörld ∀x", "héllo wörld ∀x"},
		{"invalid utf8", "a\xffb", "a�b"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			logger, buf := log.Capture()
			logger.Info(t.Context(), tt.in, log.String("k", tt.in))

			m := record(t, buf)
			if got := m["msg"]; got != tt.want {
				t.Errorf("got msg %q; want %q", got, tt.want)
			}
			if got := m["k"]; got != tt.want {
				t.Errorf("got value %q; want %q", got, tt.want)
			}
		})
	}
}

func TestSink_Levels(t *testing.T) {
	t.Parallel()

	logger, buf := log.Capture(log.WithLevel(log.LevelWarn))
	ctx := t.Context()

	logger.Error(ctx, "e")
	logger.Warn(ctx, "w")
	logger.Info(ctx, "i")
	logger.Debug(ctx, "d")
	logger.Log(ctx, log.LevelSilent, "s")
	logger.Log(ctx, log.Level(200), "x")

	if got, want := len(buf.Lines()), 2; got != want {
		t.Fatalf("got %d records; want %d: %q", got, want, buf.String())
	}
}

func TestSink_Silent(t *testing.T) {
	t.Parallel()

	logger, buf := log.Capture(log.WithLevel(log.LevelSilent))
	ctx := t.Context()

	for _, level := range []log.Level{
		log.LevelError,
		log.LevelWarn,
		log.LevelInfo,
		log.LevelDebug,
	} {
		if logger.Enabled(ctx, level) {
			t.Errorf("level %v should not be enabled", level)
		}
		logger.Log(ctx, level, "m")
	}

	if out := buf.String(); out != "" {
		t.Errorf("silent logger produced output: %q", out)
	}
}

func TestSink_Cutoff(t *testing.T) {
	t.Parallel()

	cutoff := log.NewCutoff(log.LevelError)
	logger, buf := log.Capture(log.WithCutoff(cutoff))
	ctx := t.Context()

	logger.Info(ctx, "before")
	cutoff.Set(log.LevelInfo)
	logger.Info(ctx, "after")

	lines := buf.Lines()
	if len(lines) != 1 {
		t.Fatalf("got %d records; want 1: %q", len(lines), buf.String())
	}
	if !strings.Contains(lines[0], "after") {
		t.Errorf("wrong record passed the cutoff: %q", lines[0])
	}
}

func TestSink_ContextOverride(t *testing.T) {
	t.Parallel()

	logger, buf := log.Capture(log.WithLevel(log.LevelInfo))
	ctx := t.Context()

	// The override must work in both directions: forcing debug output
	// below the threshold, and quieting levels above it.
	logger.Debug(log.SetLevel(ctx, log.LevelDebug), "verbose")
	logger.Info(log.SetLevel(ctx, log.LevelError), "quiet")
	logger.Debug(ctx, "suppressed")

	lines := buf.Lines()
	if len(lines) != 1 {
		t.Fatalf("got %d records; want 1: %q", len(lines), buf.String())
	}
	if !strings.Contains(lines[0], "verbose") {
		t.Errorf("wrong record passed the override: %q", lines[0])
	}
}

func TestSink_With(t *testing.T) {
	t.Parallel()

	logger, buf := log.Capture()
	bound := logger.With(log.String("request_id", "r1"), log.Int("n", 1))
	bound.Info(t.Context(), "m", log.String("k", "v"))

	m := record(t, buf)
	if got, want := m["request_id"], "r1"; got != want {
		t.Errorf("got %v; want %v", got, want)
	}
	if got, want := m["n"], float64(1); got != want {
		t.Errorf("got %v; want %v", got, want)
	}
	if got, want := m["k"], "v"; got != want {
		t.Errorf("got %v; want %v", got, want)
	}
}

// Sibling loggers derived from the same parent must not bleed bound
// arguments into each other, even though they extend a shared prefix.
func TestSink_With_Siblings(t *testing.T) {
	t.Parallel()

	logger, buf := log.Capture()
	parent := logger.With(log.String("app", "api"))
	a := parent.With(log.String("worker", "a"))
	b := parent.With(log.String("worker", "b"))

	ctx := t.Context()
	a.Info(ctx, "from a")
	b.Info(ctx, "from b")
	parent.Info(ctx, "from parent")

	lines := buf.Lines()
	if len(lines) != 3 {
		t.Fatalf("got %d records; want 3: %q", len(lines), buf.String())
	}

	for i, want := range []string{`"worker":"a"`, `"worker":"b"`} {
		if !strings.Contains(lines[i], want) {
			t.Errorf("line %d: want match for %q; got %q", i, want, lines[i])
		}
		if !strings.Contains(lines[i], `"app":"api"`) {
			t.Errorf("line %d: parent binding lost: %q", i, lines[i])
		}
	}
	if strings.Contains(lines[2], "worker") {
		t.Errorf("parent gained a child's binding: %q", lines[2])
	}
}

func TestSink_Child(t *testing.T) {
	t.Parallel()

	logger, buf := log.Capture()
	child := logger.Child("http").Child("server")
	child.Info(t.Context(), "m")

	if got, want := record(t, buf)["logger"], "http.server"; got != want {
		t.Errorf("got %v; want %v", got, want)
	}
}

func TestSink_Redact(t *testing.T) {
	t.Parallel()

	logger, buf := log.Capture(
		// Mixed casing, since keys derived from headers vary.
		log.WithRedact("Authorization", "password"),
	)

	// Redaction must reach bound arguments as well as call-site ones.
	logger.With(log.String("PASSWORD", "hunter2")).Info(
		t.Context(), "request",
		log.String("authorization", "Bearer abc.def"),
		log.String("path", "/login"),
	)

	out := buf.String()
	for _, secret := range []string{"Bearer abc.def", "hunter2"} {
		if strings.Contains(out, secret) {
			t.Errorf("secret %q leaked: %q", secret, out)
		}
	}
	if n := strings.Count(out, "[REDACTED]"); n != 2 {
		t.Errorf("redaction count: got %d; want 2 in %q", n, out)
	}

	if got, want := record(t, buf)["path"], "/login"; got != want {
		t.Errorf("unrelated argument was altered: got %v; want %v", got, want)
	}
}

func TestSink_ContextArgs(t *testing.T) {
	t.Parallel()

	type key struct{}

	logger, buf := log.Capture(log.WithContextArgs(
		func(ctx context.Context, args []log.Arg) []log.Arg {
			if id, ok := ctx.Value(key{}).(string); ok {
				args = append(args, log.String("trace_id", id))
			}
			return args
		},
	))

	ctx := context.WithValue(t.Context(), key{}, "t1")
	logger.Info(ctx, "m")

	if got, want := record(t, buf)["trace_id"], "t1"; got != want {
		t.Errorf("got %v; want %v", got, want)
	}
}

// Records must never interleave, even under concurrent logging.
func TestSink_Concurrent(t *testing.T) {
	t.Parallel()

	logger, buf := log.Capture()
	ctx := t.Context()

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			l := logger.With(log.Int("worker", i))
			for range 100 {
				l.Info(ctx, "message", log.String("k", "v"))
			}
		})
	}
	wg.Wait()

	lines := buf.Lines()
	if got, want := len(lines), 800; got != want {
		t.Fatalf("got %d records; want %d", got, want)
	}
	for _, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("malformed record %q: %v", line, err)
		}
	}
}

func TestMulti(t *testing.T) {
	t.Parallel()

	var buf1, buf2 log.Buffer
	logger := log.Wrap(log.Multi(
		log.NewSink(log.WithWriter(&buf1), log.WithLevel(log.LevelError)),
		log.NewSink(log.WithWriter(&buf2), log.WithLevel(log.LevelInfo)),
	))
	ctx := t.Context()

	// Enabled must be the union of the fan-out targets.
	if !logger.Enabled(ctx, log.LevelInfo) {
		t.Error("info should be enabled through the union")
	}
	if logger.Enabled(ctx, log.LevelDebug) {
		t.Error("debug should not be enabled")
	}

	logger.Error(ctx, "e")
	logger.Info(ctx, "i")

	// Records must reach only the sinks whose level admits them.
	if got, want := len(buf1.Lines()), 1; got != want {
		t.Errorf("buf1: got %d records; want %d", got, want)
	}
	if got, want := len(buf2.Lines()), 2; got != want {
		t.Errorf("buf2: got %d records; want %d", got, want)
	}
}

func TestMulti_With(t *testing.T) {
	t.Parallel()

	var buf1, buf2 log.Buffer
	logger := log.Wrap(log.Multi(
		log.NewSink(log.WithWriter(&buf1)),
		log.NewSink(log.WithWriter(&buf2)),
	))

	logger.With(log.String("k", "v")).Info(t.Context(), "m")

	for i, buf := range []*log.Buffer{&buf1, &buf2} {
		if want := `"k":"v"`; !strings.Contains(buf.String(), want) {
			t.Errorf("buf%d: want match for %q; got %q", i+1, want,
				buf.String())
		}
	}
}
