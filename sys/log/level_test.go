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
	"sync"
	"testing"

	"github.com/deep-rent/nexus/sys/log"
)

func TestLevel_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   log.Level
		want string
	}{
		{log.LevelSilent, "silent"},
		{log.LevelError, "error"},
		{log.LevelWarn, "warn"},
		{log.LevelInfo, "info"},
		{log.LevelDebug, "debug"},
		{log.Level(200), "silent"},
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

func TestParseLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in      string
		want    log.Level
		wantErr bool
	}{
		{"silent", log.LevelSilent, false},
		{"error", log.LevelError, false},
		{"warn", log.LevelWarn, false},
		{"info", log.LevelInfo, false},
		{"debug", log.LevelDebug, false},
		{"SILENT", log.LevelSilent, false},
		{"Error", log.LevelError, false},
		{"WARN", log.LevelWarn, false},
		{"Info", log.LevelInfo, false},
		{"DEBUG", log.LevelDebug, false},
		{"warning", 0, true},
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

func TestLevel_MarshalText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in      log.Level
		want    []byte
		wantErr bool
	}{
		{log.LevelSilent, []byte("silent"), false},
		{log.LevelError, []byte("error"), false},
		{log.LevelWarn, []byte("warn"), false},
		{log.LevelInfo, []byte("info"), false},
		{log.LevelDebug, []byte("debug"), false},
		{log.Level(200), nil, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.want), func(t *testing.T) {
			t.Parallel()
			got, err := tt.in.MarshalText()
			if (err != nil) != tt.wantErr {
				t.Fatalf("got err %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !bytes.Equal(got, tt.want) {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}
}

func TestLevel_AppendText(t *testing.T) {
	t.Parallel()

	b, err := log.LevelWarn.AppendText([]byte("level="))
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if got, want := string(b), "level=warn"; got != want {
		t.Errorf("got %q; want %q", got, want)
	}

	if _, err := log.Level(200).AppendText(nil); err == nil {
		t.Error("should have returned an error for an invalid level")
	}
}

// Marshaling and parsing must round-trip for every defined level, since
// configuration files rely on the textual names.
func TestLevel_RoundTrip(t *testing.T) {
	t.Parallel()

	levels := []log.Level{
		log.LevelSilent,
		log.LevelError,
		log.LevelWarn,
		log.LevelInfo,
		log.LevelDebug,
	}

	for _, level := range levels {
		text, err := level.MarshalText()
		if err != nil {
			t.Fatalf("%v: marshal failed: %v", level, err)
		}
		got, err := log.ParseLevel(string(text))
		if err != nil {
			t.Fatalf("%v: parse failed: %v", level, err)
		}
		if got != level {
			t.Errorf("round trip changed %v to %v", level, got)
		}
	}
}

func TestCutoff_ZeroValue(t *testing.T) {
	t.Parallel()

	// The zero value must cut off everything.
	var c log.Cutoff
	if got, want := c.Level(), log.LevelSilent; got != want {
		t.Errorf("got %v; want %v", got, want)
	}
}

func TestCutoff_Set(t *testing.T) {
	t.Parallel()

	c := log.NewCutoff(log.LevelInfo)
	if got, want := c.Level(), log.LevelInfo; got != want {
		t.Errorf("got %v; want %v", got, want)
	}

	c.Set(log.LevelError)
	if got, want := c.Level(), log.LevelError; got != want {
		t.Errorf("got %v; want %v", got, want)
	}

	// Out-of-range levels are clamped to debug.
	c.Set(log.Level(200))
	if got, want := c.Level(), log.LevelDebug; got != want {
		t.Errorf("got %v; want %v", got, want)
	}
}

func TestCutoff_Concurrent(t *testing.T) {
	t.Parallel()

	c := log.NewCutoff(log.LevelInfo)

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 1000 {
				c.Set(log.LevelDebug)
				_ = c.Level()
			}
		})
	}
	wg.Wait()

	if got, want := c.Level(), log.LevelDebug; got != want {
		t.Errorf("got %v; want %v", got, want)
	}
}
