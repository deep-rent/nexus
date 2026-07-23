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
	"errors"
	"testing"
	"time"

	"uuid"

	"github.com/deep-rent/nexus/sys/log"
)

func TestArg_Constructors(t *testing.T) {
	t.Parallel()

	err := errors.New("boom")
	now := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC)

	tests := []struct {
		name    string
		in      log.Arg
		wantKey string
		want    log.Kind
		wantVal any
	}{
		{
			name:    "string",
			in:      log.String("k", "v"),
			wantKey: "k",
			want:    log.KindString,
			wantVal: "v",
		},
		{
			name:    "int",
			in:      log.Int("k", -42),
			wantKey: "k",
			want:    log.KindInt64,
			wantVal: int64(-42),
		},
		{
			name:    "int8",
			in:      log.Int8("k", -8),
			wantKey: "k",
			want:    log.KindInt64,
			wantVal: int64(-8),
		},
		{
			name:    "int16",
			in:      log.Int16("k", -16),
			wantKey: "k",
			want:    log.KindInt64,
			wantVal: int64(-16),
		},
		{
			name:    "int32",
			in:      log.Int32("k", -32),
			wantKey: "k",
			want:    log.KindInt64,
			wantVal: int64(-32),
		},
		{
			name:    "int64",
			in:      log.Int64("k", 1<<40),
			wantKey: "k",
			want:    log.KindInt64,
			wantVal: int64(1 << 40),
		},
		{
			name:    "uint",
			in:      log.Uint("k", 42),
			wantKey: "k",
			want:    log.KindUint64,
			wantVal: uint64(42),
		},
		{
			name:    "uint8",
			in:      log.Uint8("k", 8),
			wantKey: "k",
			want:    log.KindUint64,
			wantVal: uint64(8),
		},
		{
			name:    "uint16",
			in:      log.Uint16("k", 16),
			wantKey: "k",
			want:    log.KindUint64,
			wantVal: uint64(16),
		},
		{
			name:    "uint32",
			in:      log.Uint32("k", 32),
			wantKey: "k",
			want:    log.KindUint64,
			wantVal: uint64(32),
		},
		{
			name:    "uint64",
			in:      log.Uint64("k", 18446744073709551615),
			wantKey: "k",
			want:    log.KindUint64,
			wantVal: uint64(18446744073709551615),
		},
		{
			name:    "float32",
			in:      log.Float32("k", 3.1),
			wantKey: "k",
			want:    log.KindFloat32,
			wantVal: float32(3.1),
		},
		{
			name:    "float64",
			in:      log.Float64("k", 3.25),
			wantKey: "k",
			want:    log.KindFloat64,
			wantVal: 3.25,
		},
		{
			name:    "bool true",
			in:      log.Bool("k", true),
			wantKey: "k",
			want:    log.KindBool,
			wantVal: true,
		},
		{
			name:    "bool false",
			in:      log.Bool("k", false),
			wantKey: "k",
			want:    log.KindBool,
			wantVal: false,
		},
		{
			name:    "duration",
			in:      log.Duration("k", -1500*time.Millisecond),
			wantKey: "k",
			want:    log.KindDuration,
			wantVal: -1500 * time.Millisecond,
		},
		{
			name:    "time",
			in:      log.Time("k", now),
			wantKey: "k",
			want:    log.KindTime,
			wantVal: now,
		},
		{
			name: "uuid",
			in: log.UUID(
				"k",
				uuid.MustParse("0195c2a7-9e4b-7c58-8000-0123456789ab"),
			),
			wantKey: "k",
			want:    log.KindString,
			wantVal: "0195c2a7-9e4b-7c58-8000-0123456789ab",
		},
		{
			name:    "error",
			in:      log.Error(err),
			wantKey: log.ErrorKey,
			want:    log.KindError,
			wantVal: err,
		},
		{
			name:    "nil error",
			in:      log.Error(nil),
			wantKey: log.ErrorKey,
			want:    log.KindError,
			wantVal: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.in.Key; got != tt.wantKey {
				t.Errorf("got key %q; want %q", got, tt.wantKey)
			}
			if got := tt.in.Kind(); got != tt.want {
				t.Errorf("got kind %v; want %v", got, tt.want)
			}
			if got := tt.in.Value(); got != tt.wantVal {
				t.Errorf("got value %v; want %v", got, tt.wantVal)
			}
		})
	}
}

// The key must stay stable, since sinks and log processors match on it.
func TestError_Key(t *testing.T) {
	t.Parallel()

	if got := log.Error(errors.New("x")).Key; got != log.ErrorKey {
		t.Errorf("got %q; want %q", got, log.ErrorKey)
	}

	if log.ErrorKey != "error" {
		t.Errorf(
			"ErrorKey changed to %q; call sites and dashboards depend on it",
			log.ErrorKey,
		)
	}
}

// Times must survive the internal Unix-nanosecond representation as the
// same instant, including when constructed in a non-UTC zone.
func TestTime_PreservesInstant(t *testing.T) {
	t.Parallel()

	zone := time.FixedZone("UTC+2", 2*60*60)
	tests := []struct {
		name string
		in   time.Time
	}{
		{"utc", time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC)},
		{"zoned", time.Date(2026, 1, 2, 3, 4, 5, 0, zone)},
		{"zero", time.Time{}},
		{"far future", time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := log.Time("k", tt.in).Value().(time.Time)
			if !ok {
				t.Fatal("value is not a time.Time")
			}
			if !got.Equal(tt.in) {
				t.Errorf("got %v; want %v", got, tt.in)
			}
		})
	}
}
