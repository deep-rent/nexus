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

package uuid_test

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deep-rent/nexus/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_Structure(t *testing.T) {
	u := uuid.New()

	version := u[6] >> 4
	assert.Equal(t, byte(7), version)

	variant := u[8] & 0xc0
	assert.Equal(t, byte(0x80), variant)
}

func TestNew_TimeAccuracy(t *testing.T) {
	u := uuid.New()
	now := time.Now()

	var ts int64
	ts |= int64(u[0]) << 40
	ts |= int64(u[1]) << 32
	ts |= int64(u[2]) << 24
	ts |= int64(u[3]) << 16
	ts |= int64(u[4]) << 8
	ts |= int64(u[5])

	assert.WithinDuration(t, now, time.UnixMilli(ts), 100*time.Millisecond)
}

func TestNew_Monotonicity(t *testing.T) {
	count := 10000
	uuids := make([]uuid.UUIDv7, count)

	for i := range count {
		uuids[i] = uuid.New()
	}

	for i := 1; i < count; i++ {
		prev := uuids[i-1]
		curr := uuids[i]

		assert.True(
			t,
			bytes.Compare(curr[:], prev[:]) > 0,
			"UUIDs must be strictly monotonic",
		)
	}
}

func TestString_Format(t *testing.T) {
	u := uuid.New()
	s := u.String()

	assert.Len(t, s, 36)
	assert.Equal(t, byte('-'), s[8])
	assert.Equal(t, byte('-'), s[13])
	assert.Equal(t, byte('-'), s[18])
	assert.Equal(t, byte('-'), s[23])

	parsed, err := uuid.Parse(s)
	require.NoError(t, err)
	assert.Equal(t, u, parsed)
}

func TestParse(t *testing.T) {
	v7 := uuid.New()

	v4 := v7
	v4[6] = (v4[6] & 0x0f) | 0x40

	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid",
			input:   v7.String(),
			wantErr: false,
		},
		{
			name:    "too short",
			input:   "018e6-123",
			wantErr: true,
			errMsg:  "uuid: invalid length",
		},
		{
			name:    "too long",
			input:   v7.String() + "a",
			wantErr: true,
			errMsg:  "uuid: invalid length",
		},
		{
			name:    "missing hyphens",
			input:   strings.ReplaceAll(v7.String(), "-", ""),
			wantErr: true,
			errMsg:  "uuid: invalid length",
		},
		{
			name:    "wrong hyphen position",
			input:   "018e66a31234-5678-9abc-def0-12345678",
			wantErr: true,
			errMsg:  "uuid: invalid format",
		},
		{
			name:    "wrong version", // v4 instead of v7
			input:   v4.String(),
			wantErr: true,
			errMsg:  "uuid: invalid version: expected v7",
		},
		{
			name: "wrong variant", // Microsoft legacy GUID
			input: func() string {
				u := v7
				u[8] = 0xC0
				return u.String()
			}(),
			wantErr: true,
			errMsg:  "uuid: invalid variant",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := uuid.Parse(tc.input)
			if tc.wantErr {
				require.Error(t, err)
				assert.ErrorContains(t, err, tc.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestParseBytes(t *testing.T) {
	v7 := uuid.New()
	v4 := v7
	v4[6] = (v4[6] & 0x0f) | 0x40

	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid bytes",
			input:   v7[:],
			wantErr: false,
		},
		{
			name:    "too short",
			input:   v7[:10],
			wantErr: true,
			errMsg:  "uuid: invalid length",
		},
		{
			name:    "too long",
			input:   append(v7[:], 0x01),
			wantErr: true,
			errMsg:  "uuid: invalid length",
		},
		{
			name:    "wrong version", // v4 instead of v7
			input:   v4[:],
			wantErr: true,
			errMsg:  "uuid: invalid version: expected v7",
		},
		{
			name: "wrong variant", // Variant 0 (NCS)
			input: func() []byte {
				u := v7
				u[8] = 0x00
				return u[:]
			}(),
			wantErr: true,
			errMsg:  "uuid: invalid variant",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, len(tc.input))
			copy(buf, tc.input)

			u, err := uuid.ParseBytes(buf)

			if tc.wantErr {
				require.Error(t, err)
				assert.ErrorContains(t, err, tc.errMsg)
			} else {
				require.NoError(t, err)
				assert.Equal(t, v7, u)
				for i := range buf { // Safety check for mutation
					buf[i] ^= 0xFF
				}
				assert.Equal(t, v7, u)
			}
		})
	}
}

func TestConcurrency(t *testing.T) {
	var wg sync.WaitGroup
	count := 100
	routines := 50

	ids := make(chan uuid.UUIDv7, count*routines)

	wg.Add(routines)
	for range routines {
		go func() {
			defer wg.Done()
			for range count {
				ids <- uuid.New()
			}
		}()
	}

	wg.Wait()
	close(ids)

	seen := make(map[uuid.UUIDv7]bool)
	for id := range ids {
		assert.False(t, seen[id], "Duplicate UUID generated: %s", id)
		seen[id] = true
	}
}

func BenchmarkNew(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = uuid.New()
		}
	})
}

func BenchmarkString(b *testing.B) {
	u := uuid.New()

	for b.Loop() {
		_ = u.String()
	}
}

func BenchmarkParse(b *testing.B) {
	s := uuid.New().String()

	for b.Loop() {
		_, _ = uuid.Parse(s)
	}
}

func BenchmarkParseBytes(b *testing.B) {
	u := uuid.New()
	input := u[:]

	b.ResetTimer()
	for b.Loop() {
		_, _ = uuid.ParseBytes(input)
	}
}
