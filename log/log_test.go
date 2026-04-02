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
			name: "with level string",
			opts: []log.Option{log.WithLevel("debug")},
		},
		{
			name: "with level const",
			opts: []log.Option{log.WithLevel(slog.LevelError)},
		},
		{
			name: "with format string",
			opts: []log.Option{log.WithFormat("json")},
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
				log.WithLevel("debug"),
				log.WithFormat("json"),
				log.WithAddSource(true),
				log.WithWriter(new(bytes.Buffer)),
			},
		},
		{
			name: "invalid level",
			opts: []log.Option{log.WithLevel("foo")},
		},
		{
			name: "invalid format",
			opts: []log.Option{log.WithFormat("bar")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := log.New(tt.opts...); got == nil {
				t.Fatalf("New() = nil; want *slog.Logger")
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
				t.Fatalf("ParseLevel(%q) error = %v; wantErr %v",
					tt.in, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseLevel(%q) = %v; want %v", tt.in, got, tt.want)
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
				t.Fatalf("ParseFormat(%q) error = %v; wantErr %v",
					tt.in, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseFormat(%q) = %v; want %v", tt.in, got, tt.want)
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
				t.Errorf("Format.String() = %q; want %q", got, tt.want)
			}
		})
	}
}

func TestSilent(t *testing.T) {
	t.Parallel()

	logger := log.Silent()
	if logger == nil {
		t.Fatalf("Silent() = nil; want *slog.Logger")
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
			t.Errorf("Silent().Enabled(ctx, %v) = true; want false", l)
		}
	}

	// Ensure it does not panic
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
		t.Fatalf("NewHandler() = nil; want slog.Handler")
	}

	if !handler.Enabled(t.Context(), slog.LevelDebug) {
		t.Errorf("NewHandler().Enabled(debug) = false; want true")
	}
}

func TestCombine(t *testing.T) {
	t.Parallel()

	var buf1, buf2 bytes.Buffer
	h1 := log.NewHandler(log.WithWriter(&buf1), log.WithFormat(log.FormatText))
	h2 := log.NewHandler(log.WithWriter(&buf2), log.WithFormat(log.FormatJSON))

	logger := log.Combine(h1, h2)
	if logger == nil {
		t.Fatalf("Combine() = nil; want *slog.Logger")
	}

	logger.Info("broadcast message", slog.String("key", "value"))

	out1 := buf1.String()
	if want := "broadcast message"; !strings.Contains(out1, want) {
		t.Errorf("buf1 missing %q; got %q", want, out1)
	}
	if want := "key=value"; !strings.Contains(out1, want) {
		t.Errorf("buf1 missing %q; got %q", want, out1)
	}

	out2 := buf2.String()
	if want := "broadcast message"; !strings.Contains(out2, want) {
		t.Errorf("buf2 missing %q; got %q", want, out2)
	}
	if want := `"key":"value"`; !strings.Contains(out2, want) {
		t.Errorf("buf2 missing %q; got %q", want, out2)
	}
}
