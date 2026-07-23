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

func TestRecorder(t *testing.T) {
	t.Parallel()

	rec := log.NewRecorder()
	logger := log.Wrap(rec).Child("http")
	logger.Warn(t.Context(), "m", log.Int("n", 7))

	records := rec.Records()
	if len(records) != 1 {
		t.Fatalf("got %d records; want 1", len(records))
	}

	r := records[0]
	if got, want := r.Level, log.LevelWarn; got != want {
		t.Errorf("got level %v; want %v", got, want)
	}
	if got, want := r.Logger, "http"; got != want {
		t.Errorf("got logger %q; want %q", got, want)
	}
	if got, want := r.Msg, "m"; got != want {
		t.Errorf("got msg %q; want %q", got, want)
	}
	if r.Time.IsZero() {
		t.Error("record time should be set")
	}
	if len(r.Args) != 1 || r.Args[0].Value() != int64(7) {
		t.Errorf("got args %v; want [n=7]", r.Args)
	}
}

func TestRecorder_Enabled(t *testing.T) {
	t.Parallel()

	rec := log.NewRecorder()
	ctx := t.Context()

	for _, level := range []log.Level{
		log.LevelError,
		log.LevelWarn,
		log.LevelInfo,
		log.LevelDebug,
	} {
		if !rec.Enabled(ctx, level) {
			t.Errorf("level %v should be enabled", level)
		}
	}

	if rec.Enabled(ctx, log.LevelSilent) {
		t.Error("silent should not be enabled")
	}
	if rec.Enabled(ctx, log.Level(200)) {
		t.Error("invalid levels should not be enabled")
	}
}

// Arguments bound via With must be materialized into captured records,
// ahead of the call-site arguments, and captures made through a derived
// sink must remain visible on the original recorder.
func TestRecorder_With(t *testing.T) {
	t.Parallel()

	rec := log.NewRecorder()
	logger := log.Wrap(rec).With(log.String("request_id", "r1"))
	logger.Info(t.Context(), "m", log.Int("n", 7))

	records := rec.Records()
	if len(records) != 1 {
		t.Fatalf("got %d records; want 1", len(records))
	}

	args := records[0].Args
	if len(args) != 2 {
		t.Fatalf("got %d args; want 2", len(args))
	}
	if got, want := args[0].Key, "request_id"; got != want {
		t.Errorf("got first key %q; want %q", got, want)
	}
	if got, want := args[1].Key, "n"; got != want {
		t.Errorf("got second key %q; want %q", got, want)
	}
}

func TestRecorder_Reset(t *testing.T) {
	t.Parallel()

	rec := log.NewRecorder()
	logger := log.Wrap(rec)
	logger.Info(t.Context(), "m")

	rec.Reset()
	if got := rec.Records(); len(got) != 0 {
		t.Errorf("got %d records after reset; want 0", len(got))
	}
}
