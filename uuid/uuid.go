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

// Package uuid provides an implementation of Version 7 UUIDs.
//
// Package uuid provides an implementation of Version 7 (Time-ordered)
// Universally Unique Identifiers (UUID) as defined in RFC 4122 and RFC 9562.
//
// # Migration Note (v4 -> v7)
//
// We migrated from UUIDv4 (fully random) to UUIDv7 (time-ordered) to improve
// database performance. UUIDv4 causes significant index fragmentation and
// random I/O in B-Tree structures (standard database primary keys) due to its
// lack of locality.
//
// UUIDv7 solves this by being strictly monotonic while retaining global
// uniqueness. This results in "append-only" index behavior, higher write
// throughput, and better cache locality. It also aligns with native support
// arriving in PostgreSQL 18+.
//
// # Usage
//
// Generate a new time-ordered identifier or parse an existing string.
//
// Example:
//
//	id := uuid.New()
//	fmt.Println(id.String())
package uuid

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"time"
)

// UUIDv7 is a 128-bit time-ordered identifier (16 bytes).
//
// Layout:
//   - 48 bits: Unix Timestamp (milliseconds)
//   - 4 bits: Version (0111)
//   - 12 bits: Random Data A
//   - 2 bits: Variant (10)
//   - 62 bits: Random Data B
type UUIDv7 [16]byte

// String returns the canonical hyphenated string representation of the
// [UUIDv7].
//
// Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
func (u UUIDv7) String() string {
	buf := make([]byte, 36)
	hex.Encode(buf[0:8], u[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], u[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], u[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], u[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:], u[10:])
	return string(buf)
}

// MarshalJSON transforms the UUIDv7 into a JSON string.
func (u UUIDv7) MarshalJSON() ([]byte, error) {
	return []byte(`"` + u.String() + `"`), nil
}

// UnmarshalJSON parses a JSON string into a UUIDv7.
func (u *UUIDv7) UnmarshalJSON(b []byte) error {
	// Remove quotes from the JSON string
	if len(b) < 2 || b[0] != '"' || b[len(b)-1] != '"' {
		return fmt.Errorf("uuid: invalid json string")
	}

	parsed, err := Parse(string(b[1 : len(b)-1]))
	if err != nil {
		return err
	}

	*u = parsed
	return nil
}

// EqualString checks if the [UUIDv7] matches the provided hyphenated string.
// It is highly optimized to avoid allocations and exits early on a mismatch.
func (u UUIDv7) EqualString(s string) bool {
	if len(s) != 36 {
		return false
	}

	// Quick check for proper hyphenation:
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}

	// We compare the hex pairs in the string to the bytes in u.
	// Groups: 8-4-4-4-12 chars -> 4-2-2-2-6 bytes
	// Total 16 bytes.

	// Group 1 (8 chars -> bytes 0-3)
	if !compareHex(s[0:8], u[0:4]) {
		return false
	}
	// Group 2 (4 chars -> bytes 4-5)
	if !compareHex(s[9:13], u[4:6]) {
		return false
	}
	// Group 3 (4 chars -> bytes 6-7)
	if !compareHex(s[14:18], u[6:8]) {
		return false
	}
	// Group 4 (4 chars -> bytes 8-9)
	if !compareHex(s[19:23], u[8:10]) {
		return false
	}
	// Group 5 (12 chars -> bytes 10-15)
	if !compareHex(s[24:36], u[10:16]) {
		return false
	}

	return true
}

// New generates a strictly monotonic [UUIDv7] with sub-millisecond precision.
//
// It fills the timestamp and sequence fields using a global monotonic counter
// derived from the system clock, ensuring that IDs generated within the same
// millisecond are ordered. The remaining bits are filled with cryptographically
// secure random data.
func New() UUIDv7 {
	ms, seq := tick()

	var u UUIDv7

	// Fill the first 6 bytes with the timestamp (big endian style).
	// Fill bytes 7 and 8 with the version and sequence.
	u[0] = byte(ms >> 40)      //nolint:gosec
	u[1] = byte(ms >> 32)      //nolint:gosec
	u[2] = byte(ms >> 24)      //nolint:gosec
	u[3] = byte(ms >> 16)      //nolint:gosec
	u[4] = byte(ms >> 8)       //nolint:gosec
	u[5] = byte(ms)            //nolint:gosec
	u[6] = 0x70 | byte(seq>>8) //nolint:gosec
	u[7] = byte(seq)           //nolint:gosec

	// Fill bytes 8 to 15 with random data.
	if _, err := io.ReadFull(rand.Reader, u[8:]); err != nil {
		panic(fmt.Errorf("uuid: failed to read random bytes: %w", err))
	}

	// Set byte 8 to the variant.
	u[8] = (u[8] & 0x3f) | 0x80

	return u
}

// Parse converts a 36-character hyphenated string into a [UUIDv7].
//
// It strictly validates that the UUID is Version 7 and Variant 1 (RFC 4122).
func Parse(s string) (UUIDv7, error) {
	var u UUIDv7
	if len(s) != 36 {
		return u, fmt.Errorf("uuid: invalid length (%d)", len(s))
	}
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return u, fmt.Errorf("uuid: invalid format")
	}
	h := s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:]
	if _, err := hex.Decode(u[:], []byte(h)); err != nil {
		return u, fmt.Errorf("uuid: invalid characters: %w", err)
	}
	if (u[6] & 0xf0) != 0x70 {
		return UUIDv7{}, fmt.Errorf("uuid: invalid version: expected v7")
	}
	if (u[8] & 0xc0) != 0x80 {
		return UUIDv7{}, fmt.Errorf("uuid: invalid variant: expected RFC 4122")
	}
	return u, nil
}

// ParseBytes parses a 16-byte raw slice into a [UUIDv7].
//
// It strictly validates that the byte slice is exactly 16 bytes and conforms
// to Version 7 and Variant 1. This function creates a complete copy of the
// data.
func ParseBytes(b []byte) (UUIDv7, error) {
	var u UUIDv7
	if len(b) != 16 {
		return u, fmt.Errorf("uuid: invalid length (%d)", len(b))
	}
	copy(u[:], b)
	if (u[6] & 0xf0) != 0x70 {
		return UUIDv7{}, fmt.Errorf("uuid: invalid version: expected v7")
	}
	if (u[8] & 0xc0) != 0x80 {
		return UUIDv7{}, fmt.Errorf("uuid: invalid variant: expected RFC 4122")
	}
	return u, nil
}

// Global state for the monotonic generator.
var (
	// mu protects the last generated timestamp state.
	mu sync.Mutex
	// last is the combined scalar of the last generated timestamp and sequence.
	last int64
)

// tick implements Method 3 from the UUIDv7 specification (RFC 9562, Section
// 6.2).
//
// It returns a timestamp (ms) and a strictly increasing sequence (seq). The
// sequence holds fractional nanoseconds scaled to fit into 12 bits.
func tick() (ms, seq int64) {
	mu.Lock()
	defer mu.Unlock()

	// 1. Get current time components.
	ns := time.Now().UnixNano()
	ms = ns / 1_000_000

	// 2. Calculate the sequence number.
	// We have 1,000,000 nanoseconds in a millisecond.
	// We have 12 bits for the sequence (max 4096).
	// Dividing by 256 (>> 8) maps 1,000,000 to ~3906, which fits in 12 bits.
	seq = (ns - ms*1_000_000) >> 8

	// 3. Pack into a comparable scalar (48 bits MS + 12 bits SEQ).
	ts := ms<<12 + seq

	// 4. Enforce monotonicity.
	if ts <= last {
		ts = last + 1
		// Unpack the scalar back into components.
		// If seq overflowed 12 bits, it automatically increments ms.
		ms = ts >> 12
		seq = ts & 0xfff
	}

	last = ts
	return ms, seq
}

// compareHex compares a hex-encoded string segment to a byte slice.
func compareHex(s string, b []byte) bool {
	for i := range b {
		// Convert two hex chars to one byte
		hi := decodeHex(s[i*2])
		lo := decodeHex(s[i*2+1])

		if hi == 0xff || lo == 0xff || (hi<<4|lo) != b[i] {
			return false
		}
	}
	return true
}

// decodeHex converts a single hex character to its byte value.
// Returns 0xff if the character is invalid.
func decodeHex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0xff
}
