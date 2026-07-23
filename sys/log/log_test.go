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
	"testing"

	"github.com/deep-rent/nexus/sys/log"
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
			name: "with level",
			opts: []log.Option{log.WithLevel(log.LevelError)},
		},
		{
			name: "with cutoff",
			opts: []log.Option{log.WithCutoff(log.NewCutoff(log.LevelWarn))},
		},
		{
			name: "with nil cutoff",
			opts: []log.Option{log.WithCutoff(nil)},
		},
		{
			name: "with writer",
			opts: []log.Option{log.WithWriter(new(log.Buffer))},
		},
		{
			name: "with nil writer",
			opts: []log.Option{log.WithWriter(nil)},
		},
		{
			name: "with nil context args",
			opts: []log.Option{log.WithContextArgs(nil)},
		},
		{
			name: "all options",
			opts: []log.Option{
				log.WithLevel(log.LevelDebug),
				log.WithWriter(new(log.Buffer)),
				log.WithRedact("password"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			logger := log.New(tt.opts...)
			if logger == nil {
				t.Fatal("should not have returned nil")
			}
			if logger.Sink() == nil {
				t.Fatal("should not have a nil sink")
			}
		})
	}
}

func TestWrap_Nil(t *testing.T) {
	t.Parallel()

	logger := log.Wrap(nil)
	if logger == nil {
		t.Fatal("should not have returned nil")
	}

	// A nil sink must yield an inert logger, not a panicking one.
	logger.Info(t.Context(), "m")
	if logger.Enabled(t.Context(), log.LevelError) {
		t.Error("no level should be enabled")
	}
}

func TestLogger_Hierarchy(t *testing.T) {
	t.Parallel()

	root := log.New(log.WithWriter(new(log.Buffer)))
	if got := root.Name(); got != "" {
		t.Errorf("got root name %q; want empty", got)
	}
	if got := root.Path(); got != "" {
		t.Errorf("got root path %q; want empty", got)
	}
	if got := root.Parent(); got != nil {
		t.Errorf("got root parent %v; want nil", got)
	}

	child := root.Child("http")
	grand := child.Child("server")

	if got, want := grand.Name(), "server"; got != want {
		t.Errorf("got name %q; want %q", got, want)
	}
	if got, want := grand.Path(), "http.server"; got != want {
		t.Errorf("got path %q; want %q", got, want)
	}
	if got, want := grand.Parent(), child; got != want {
		t.Errorf("got parent %v; want %v", got, want)
	}
	if got, want := child.Parent(), root; got != want {
		t.Errorf("got parent %v; want %v", got, want)
	}

	// Deriving must share the sink, not copy it.
	if grand.Sink() != root.Sink() {
		t.Error("child does not share the root sink")
	}
}

func TestLogger_Child_Empty(t *testing.T) {
	t.Parallel()

	logger := log.Discard()
	if got := logger.Child(""); got != logger {
		t.Error("empty name should return the receiver unchanged")
	}
}

func TestLogger_With_Empty(t *testing.T) {
	t.Parallel()

	logger := log.Discard()
	if got := logger.With(); got != logger {
		t.Error("empty bindings should return the receiver unchanged")
	}
}

func TestLogger_Enabled(t *testing.T) {
	t.Parallel()

	logger := log.New(
		log.WithLevel(log.LevelInfo),
		log.WithWriter(new(log.Buffer)),
	)
	ctx := t.Context()

	tests := []struct {
		name  string
		level log.Level
		want  bool
	}{
		{"error", log.LevelError, true},
		{"warn", log.LevelWarn, true},
		{"info", log.LevelInfo, true},
		{"debug", log.LevelDebug, false},
		{"silent", log.LevelSilent, false},
		{"invalid", log.Level(200), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := logger.Enabled(ctx, tt.level); got != tt.want {
				t.Errorf("got %v; want %v", got, tt.want)
			}
		})
	}
}

func TestLogger_NilContext(t *testing.T) {
	t.Parallel()

	logger, buf := log.Capture()

	// A nil context must be tolerated, not passed on to the sink.
	logger.Info(nil, "m") //nolint:staticcheck // deliberate nil context
	if got, want := len(buf.Lines()), 1; got != want {
		t.Errorf("got %d records; want %d", got, want)
	}
	if logger.Enabled(nil, log.LevelInfo) != true { //nolint:staticcheck
		t.Error("info should be enabled")
	}
}

func TestDiscard(t *testing.T) {
	t.Parallel()

	logger := log.Discard()
	if logger == nil {
		t.Fatal("should not have returned nil")
	}

	ctx := t.Context()
	levels := []log.Level{
		log.LevelError,
		log.LevelWarn,
		log.LevelInfo,
		log.LevelDebug,
	}

	for _, level := range levels {
		if logger.Enabled(ctx, level) {
			t.Errorf("level %v should not be enabled", level)
		}
	}

	// Ensure logging, deriving, and binding do not panic.
	logger.Child("http").With(log.String("k", "v")).Error(ctx, "m")
}
