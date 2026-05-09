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
	"encoding/json/v2"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deep-rent/nexus/uuid"
)

func TestStructure(t *testing.T) {
	t.Parallel()

	u := uuid.New()

	if got, want := u[6]>>4, byte(7); got != want {
		t.Errorf("u[6] version bits = %d; want %d", got, want)
	}

	if got, want := u[8]&0xc0, byte(0x80); got != want {
		t.Errorf("u[8] variant bits = %x; want %x", got, want)
	}
}

func TestTimeAccuracy(t *testing.T) {
	t.Parallel()

	const tolerance = 100 * time.Millisecond

	u := uuid.New()
	now := time.Now()

	var ts int64
	ts |= int64(u[0]) << 40
	ts |= int64(u[1]) << 32
	ts |= int64(u[2]) << 24
	ts |= int64(u[3]) << 16
	ts |= int64(u[4]) << 8
	ts |= int64(u[5])

	got := time.UnixMilli(ts)
	if diff := now.Sub(got); diff < -tolerance || diff > tolerance {
		t.Errorf("UUID timestamp = %v; current time = %v; diff = %v",
			got, now, diff)
	}
}

func TestMonotonicity(t *testing.T) {
	t.Parallel()

	const count = 10000
	uuids := make([]uuid.UUIDv7, count)

	for i := range count {
		uuids[i] = uuid.New()
	}

	for i := 1; i < count; i++ {
		prev := uuids[i-1]
		curr := uuids[i]

		if bytes.Compare(curr[:], prev[:]) <= 0 {
			t.Errorf("UUID[%d] (%s) is not greater than UUID[%d] (%s)",
				i, curr, i-1, prev)
		}
	}
}

func TestString(t *testing.T) {
	t.Parallel()

	u := uuid.New()
	s := u.String()

	if got, want := len(s), 36; got != want {
		t.Errorf("len(u.String()) = %d; want %d", got, want)
	}

	indices := []int{8, 13, 18, 23}
	for _, idx := range indices {
		if s[idx] != '-' {
			t.Errorf("s[%d] = %q; want '-'", idx, s[idx])
		}
	}

	parsed, err := uuid.Parse(s)
	if err != nil {
		t.Fatalf("uuid.Parse(%q) err = %v", s, err)
	}
	if parsed != u {
		t.Errorf("uuid.Parse(%q) = %v; want %v", s, parsed, u)
	}
}

func TestParse(t *testing.T) {
	t.Parallel()

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
			name:    "wrong version",
			input:   v4.String(),
			wantErr: true,
			errMsg:  "uuid: invalid version: expected v7",
		},
		{
			name: "wrong variant",
			input: func() string {
				u := v7
				u[8] = 0xC0
				return u.String()
			}(),
			wantErr: true,
			errMsg:  "uuid: invalid variant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := uuid.Parse(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Parse(%q) err = nil; want error %q",
						tt.input, tt.errMsg)
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("err = %q; want to contain %q",
						err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("Parse(%q) err = %v; want nil", tt.input, err)
			}
		})
	}
}

func TestParseBytes(t *testing.T) {
	t.Parallel()

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
			name:    "wrong version",
			input:   v4[:],
			wantErr: true,
			errMsg:  "uuid: invalid version: expected v7",
		},
		{
			name: "wrong variant",
			input: func() []byte {
				u := v7
				u[8] = 0x00
				return u[:]
			}(),
			wantErr: true,
			errMsg:  "uuid: invalid variant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			buf := make([]byte, len(tt.input))
			copy(buf, tt.input)

			u, err := uuid.ParseBytes(buf)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseBytes() err = nil; want error %q",
						tt.errMsg)
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("err = %q; want to contain %q",
						err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseBytes() err = %v; want nil", err)
			}
			if u != v7 {
				t.Errorf("ParseBytes() = %v; want %v", u, v7)
			}

			// Mutation safety check
			for i := range buf {
				buf[i] ^= 0xFF
			}
			if u != v7 {
				t.Error("ParseBytes result was mutated by modifying input buffer")
			}
		})
	}
}

func TestNew_Concurrency_Unique(t *testing.T) {
	t.Parallel()

	var wg sync.WaitGroup
	const count = 100
	const routines = 50

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

	seen := make(map[uuid.UUIDv7]struct{})
	for id := range ids {
		if _, exists := seen[id]; exists {
			t.Errorf("Duplicate UUID generated: %s", id)
		}
		seen[id] = struct{}{}
	}
}

func TestJSON(t *testing.T) {
	t.Parallel()

	t.Run("Marshal", func(t *testing.T) {
		u, err := uuid.Parse("018f3a00-0000-7000-8000-000000000000")
		if err != nil {
			t.Fatal(err)
		}

		got, err := json.Marshal(u)
		if err != nil {
			t.Fatalf("json.Marshal() err = %v", err)
		}

		want := []byte(`"018f3a00-0000-7000-8000-000000000000"`)
		if !bytes.Equal(got, want) {
			t.Errorf("json.Marshal() = %s; want %s", got, want)
		}
	})

	t.Run("UnmarshalValid", func(t *testing.T) {
		input := []byte(`"018f3a55-1234-7000-8abc-def012345678"`)
		var u uuid.UUIDv7

		if err := json.Unmarshal(input, &u); err != nil {
			t.Fatalf("json.Unmarshal() err = %v", err)
		}

		if got, want := u.String(),
			"018f3a55-1234-7000-8abc-def012345678"; got != want {
			t.Errorf("Unmarshaled UUID = %s; want %s", got, want)
		}
	})

	t.Run("UnmarshalInvalid", func(t *testing.T) {
		tests := []struct {
			name  string
			input string
		}{
			{"not a string", `12345`},
			{"invalid uuid format", `"not-a-uuid"`},
			{"wrong version", `"018f3a55-1234-4000-8abc-def012345678"`},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var u uuid.UUIDv7
				err := json.Unmarshal([]byte(tt.input), &u)
				if err == nil {
					t.Errorf("Unmarshal(%s) expected error, got nil", tt.input)
				}
			})
		}
	})
}

func TestJSONInStruct(t *testing.T) {
	t.Parallel()

	type User struct {
		ID   uuid.UUIDv7 `json:"id"`
		Name string      `json:"name"`
	}

	u := uuid.New()
	user := User{ID: u, Name: "Alice"}

	data, err := json.Marshal(user)
	if err != nil {
		t.Fatalf("Marshal struct err = %v", err)
	}

	var decoded User
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal struct err = %v", err)
	}

	if decoded.ID != u {
		t.Errorf("Decoded ID = %v; want %v", decoded.ID, u)
	}
}

func TestEqualString(t *testing.T) {
	t.Parallel()

	u := uuid.New()
	s := u.String()

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "exact match (lowercase)",
			input: s,
			want:  true,
		},
		{
			name:  "exact match (uppercase)",
			input: strings.ToUpper(s),
			want:  true,
		},
		{
			name:  "invalid length (too short)",
			input: s[:35],
			want:  false,
		},
		{
			name:  "invalid length (too long)",
			input: s + "f",
			want:  false,
		},
		{
			name:  "missing hyphen at index 8",
			input: s[:8] + "0" + s[9:],
			want:  false,
		},
		{
			name:  "missing hyphen at index 23",
			input: s[:23] + "0" + s[24:],
			want:  false,
		},
		{
			name:  "invalid hex character",
			input: s[:7] + "g" + s[8:],
			want:  false,
		},
		{
			name: "mismatch in first byte",
			input: func() string {
				orig := s[0]
				var replacement byte = 'a'
				if orig == 'a' {
					replacement = 'b'
				}
				return string(replacement) + s[1:]
			}(),
			want: false,
		},
		{
			name: "mismatch in last byte",
			input: func() string {
				orig := s[35]
				var replacement byte = '1'
				if orig == '1' {
					replacement = '2'
				}
				return s[:35] + string(replacement)
			}(),
			want: false,
		},
		{
			name:  "empty string",
			input: "",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := u.EqualString(tt.input); got != tt.want {
				t.Errorf("EqualString(%q) = %v; want %v", tt.input, got, tt.want)
			}
		})
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

func BenchmarkEqualString(b *testing.B) {
	u := uuid.New()
	s := u.String()

	b.ResetTimer()
	for b.Loop() {
		_ = u.EqualString(s)
	}
}
