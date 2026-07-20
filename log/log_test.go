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
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/deep-rent/nexus/log"
)

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts []log.Option
	}{
		{
			name: "no options",
			opts: []log.Option{},
		},
		{
			name: "with level const",
			opts: []log.Option{log.WithLevel(slog.LevelError)},
		},
		{
			name: "with format const",
			opts: []log.Option{log.WithFormat(log.FormatJSON)},
		},
		{
			name: "with add source",
			opts: []log.Option{log.WithAddSource(true)},
		},
		{
			name: "with writer",
			opts: []log.Option{log.WithWriter(new(bytes.Buffer))},
		},
		{
			name: "with nil writer",
			opts: []log.Option{log.WithWriter(nil)},
		},
		{
			name: "all options",
			opts: []log.Option{
				log.WithLevel(slog.LevelDebug),
				log.WithFormat(log.FormatJSON),
				log.WithAddSource(true),
				log.WithWriter(new(bytes.Buffer)),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := log.New(tt.opts...); got == nil {
				t.Fatal("should not have returned nil")
			}
		})
	}
}

func TestParseLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in      string
		want    slog.Level
		wantErr bool
	}{
		{"debug", slog.LevelDebug, false},
		{"info", slog.LevelInfo, false},
		{"warn", slog.LevelWarn, false},
		{"error", slog.LevelError, false},
		{"DEBUG", slog.LevelDebug, false},
		{"INFO", slog.LevelInfo, false},
		{"Warn", slog.LevelWarn, false},
		{"Error", slog.LevelError, false},
		{"invalid", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got, err := log.ParseLevel(tt.in)
			if (err != nil) != tt.wantErr {
				if tt.wantErr {
					t.Fatal("should have returned an error")
				}
				t.Fatalf("should not have returned an error: %v", err)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("got %v; want %v", got, tt.want)
			}
		})
	}
}

func TestParseFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in      string
		want    log.Format
		wantErr bool
	}{
		{"text", log.FormatText, false},
		{"json", log.FormatJSON, false},
		{"TEXT", log.FormatText, false},
		{"JSON", log.FormatJSON, false},
		{"Text", log.FormatText, false},
		{"Json", log.FormatJSON, false},
		{"invalid", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got, err := log.ParseFormat(tt.in)
			if (err != nil) != tt.wantErr {
				if tt.wantErr {
					t.Fatal("should have returned an error")
				}
				t.Fatalf("should not have returned an error: %v", err)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("got %v; want %v", got, tt.want)
			}
		})
	}
}

func TestFormat_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   log.Format
		want string
	}{
		{log.FormatText, "text"},
		{log.FormatJSON, "json"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if got := tt.in.String(); got != tt.want {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}
}

func TestFormat_MarshalText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in      log.Format
		want    []byte
		wantErr bool
	}{
		{log.FormatText, []byte("text"), false},
		{log.FormatJSON, []byte("json"), false},
		{log.Format(255), nil, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.want), func(t *testing.T) {
			t.Parallel()
			got, err := tt.in.MarshalText()
			if (err != nil) != tt.wantErr {
				t.Fatalf("got err %v, wantErr %v", err, tt.wantErr)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}
}

func TestFormat_UnmarshalText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in      []byte
		want    log.Format
		wantErr bool
	}{
		{[]byte("text"), log.FormatText, false},
		{[]byte("json"), log.FormatJSON, false},
		{[]byte("TEXT"), log.FormatText, false},
		{[]byte("JSON"), log.FormatJSON, false},
		{[]byte("invalid"), 0, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.in), func(t *testing.T) {
			t.Parallel()
			var got log.Format
			err := got.UnmarshalText(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("got err %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("got %v; want %v", got, tt.want)
			}
		})
	}
}

func TestSilent(t *testing.T) {
	t.Parallel()

	logger := log.Silent()
	if logger == nil {
		t.Fatal("should not have returned nil")
	}

	ctx := t.Context()
	levels := []slog.Level{
		slog.LevelDebug,
		slog.LevelInfo,
		slog.LevelWarn,
		slog.LevelError,
	}

	for _, l := range levels {
		if logger.Enabled(ctx, l) {
			t.Errorf("level %v should not be enabled", l)
		}
	}

	// Ensure it does not panic.
	logger.Error("test message", "key", "value")
}

func TestNewHandler(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	handler := log.NewHandler(
		log.WithLevel(slog.LevelDebug),
		log.WithWriter(&buf),
	)

	if handler == nil {
		t.Fatal("should not have returned nil")
	}

	if !handler.Enabled(t.Context(), slog.LevelDebug) {
		t.Error("debug level should be enabled")
	}
}

func TestCombine(t *testing.T) {
	t.Parallel()

	var buf1, buf2 bytes.Buffer
	h1 := log.NewHandler(log.WithWriter(&buf1), log.WithFormat(log.FormatText))
	h2 := log.NewHandler(log.WithWriter(&buf2), log.WithFormat(log.FormatJSON))

	logger := log.Combine(h1, h2)
	if logger == nil {
		t.Fatal("should not have returned nil")
	}

	logger.Info("broadcast message", slog.String("key", "value"))

	out1 := buf1.String()
	if want := "broadcast message"; !strings.Contains(out1, want) {
		t.Errorf("buf1: want match for %q; got %q", want, out1)
	}
	if want := "key=value"; !strings.Contains(out1, want) {
		t.Errorf("buf1: want match for %q; got %q", want, out1)
	}

	out2 := buf2.String()
	if want := "broadcast message"; !strings.Contains(out2, want) {
		t.Errorf("buf2: want match for %q; got %q", want, out2)
	}
	if want := `"key":"value"`; !strings.Contains(out2, want) {
		t.Errorf("buf2: want match for %q; got %q", want, out2)
	}
}

func TestWithReplaceAttr(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := log.New(
		log.WithWriter(&buf),
		log.WithReplaceAttr(func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == "password" {
				return slog.String(a.Key, "[REDACTED]")
			}
			return a
		}),
	)

	logger.Info("login", "user", "alice", "password", "hunter2")

	logs := buf.String()
	if strings.Contains(logs, "hunter2") {
		t.Errorf("secret was not redacted: %q", logs)
	}
	if !strings.Contains(logs, "[REDACTED]") {
		t.Errorf("redaction marker missing: %q", logs)
	}
	if !strings.Contains(logs, "user=alice") {
		t.Errorf("unrelated attribute was altered: %q", logs)
	}
}

func TestWithReplaceAttr_Nil(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := log.New(log.WithWriter(&buf), log.WithReplaceAttr(nil))

	// A nil replacer must be ignored, leaving attributes untouched.
	logger.Info("event", "key", "value")

	if !strings.Contains(buf.String(), "key=value") {
		t.Errorf("nil replacer changed behavior: %q", buf.String())
	}
}

func TestRedact(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := log.New(
		log.WithWriter(&buf),
		// Mixed casing, since keys derived from headers vary.
		log.Redact("Authorization", "password"),
	)

	logger.Info("request",
		slog.String("authorization", "Bearer abc.def"),
		slog.String("PASSWORD", "hunter2"),
		slog.String("path", "/login"),
	)

	logs := buf.String()

	for _, secret := range []string{"Bearer abc.def", "hunter2"} {
		if strings.Contains(logs, secret) {
			t.Errorf("secret %q leaked: %q", secret, logs)
		}
	}

	if !strings.Contains(logs, "path=/login") {
		t.Errorf("unrelated attribute was altered: %q", logs)
	}

	if n := strings.Count(logs, "[REDACTED]"); n != 2 {
		t.Errorf("redaction count: got %d; want 2 in %q", n, logs)
	}
}

func TestRedact_NoKeys(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := log.New(log.WithWriter(&buf), log.Redact())

	logger.Info("event", "key", "value")

	if !strings.Contains(buf.String(), "key=value") {
		t.Errorf("empty redact set altered output: %q", buf.String())
	}
}

func TestErr(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := log.New(log.WithWriter(&buf), log.WithFormat(log.FormatJSON))

	logger.Error("request failed", log.Err(errors.New("connection refused")))

	logs := buf.String()
	if !strings.Contains(logs, `"error":"connection refused"`) {
		t.Errorf("error not recorded under the canonical key: %q", logs)
	}
}

// The key must stay stable, since handlers and log processors match on it.
func TestErr_Key(t *testing.T) {
	t.Parallel()

	if got := log.Err(errors.New("x")).Key; got != log.ErrorKey {
		t.Errorf("got %q; want %q", got, log.ErrorKey)
	}

	if log.ErrorKey != "error" {
		t.Errorf("ErrorKey changed to %q; call sites and dashboards depend on it",
			log.ErrorKey)
	}
}

// A wrapped error must keep its full message, including under JSON where a
// naive marshal of the underlying type would lose it.
func TestErr_PreservesWrappedMessage(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := log.New(log.WithWriter(&buf), log.WithFormat(log.FormatJSON))

	err := fmt.Errorf("querying users: %w", errors.New("timeout"))
	logger.Error("failed", log.Err(err))

	if !strings.Contains(buf.String(), "querying users: timeout") {
		t.Errorf("wrapped message lost: %q", buf.String())
	}
}
