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

	uuidTime := time.UnixMilli(ts)
	assert.WithinDuration(t, now, uuidTime, 100*time.Millisecond)
}

func TestNew_Monotonicity(t *testing.T) {
	count := 10000
	uuids := make([]uuid.UUIDv7, count)

	for i := 0; i < count; i++ {
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
	validV7 := uuid.New()
	validStr := validV7.String()

	v4Bytes := validV7
	v4Bytes[6] = (v4Bytes[6] & 0x0f) | 0x40
	v4Str := v4Bytes.String()

	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "Valid UUIDv7",
			input:   validStr,
			wantErr: false,
		},
		{
			name:    "Invalid Length (Short)",
			input:   "018e6-123",
			wantErr: true,
			errMsg:  "invalid UUID length",
		},
		{
			name:    "Invalid Length (Long)",
			input:   validStr + "a",
			wantErr: true,
			errMsg:  "invalid UUID length",
		},
		{
			name:    "Missing Hyphens",
			input:   strings.ReplaceAll(validStr, "-", ""),
			wantErr: true,
			errMsg:  "invalid UUID length",
		},
		{
			name:    "Wrong Hyphen Position",
			input:   "018e66a31234-5678-9abc-def0-12345678",
			wantErr: true,
			errMsg:  "invalid UUID format",
		},
		{
			name:    "Non-Hex Characters",
			input:   strings.Replace(validStr, "a", "z", 1),
			wantErr: true,
			errMsg:  "invalid UUID characters",
		},
		{
			name:    "Wrong Version (v4)",
			input:   v4Str,
			wantErr: true,
			errMsg:  "uuid: invalid version: expected v7",
		},
		{
			name: "Wrong Variant (Microsoft GUID legacy)",
			input: func() string {
				u := validV7
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

func TestConcurrency(t *testing.T) {
	var wg sync.WaitGroup
	count := 100
	routines := 50

	ids := make(chan uuid.UUIDv7, count*routines)

	wg.Add(routines)
	for r := 0; r < routines; r++ {
		go func() {
			defer wg.Done()
			for i := 0; i < count; i++ {
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
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = u.String()
	}
}

func BenchmarkParse(b *testing.B) {
	s := uuid.New().String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = uuid.Parse(s)
	}
}
