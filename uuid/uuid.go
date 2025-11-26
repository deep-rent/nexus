// Package uuid provides an implementation of Version 7 (Time-ordered)
// Universally Unique Identifiers (UUID) as defined in RFC 9562.
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
// - 48 bits: Unix Timestamp (milliseconds)
// -  4 bits: Version (0111)
// - 12 bits: Random Data A
// -  2 bits: Variant (10)
// - 62 bits: Random Data B
type UUIDv7 [16]byte

// String returns the canonical string representation of the UUIDv7.
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

// New generates a strictly monotonic UUIDv7 with sub-millisecond precision.
//
// It fills the timestamp and sequence fields using a global monotonic counter
// derived from the system clock, ensuring that IDs generated within the same
// millisecond are ordered. The remaining bits are filled with cryptographically
// secure random data.
func New() UUIDv7 {
	ms, seq := count()

	var u UUIDv7

	// Fill the first 6 bytes with the timestamp (Big Endian).
	u[0] = byte(ms >> 40)
	u[1] = byte(ms >> 32)
	u[2] = byte(ms >> 24)
	u[3] = byte(ms >> 16)
	u[4] = byte(ms >> 8)
	u[5] = byte(ms)
	// Fill bytes 6 and 7 with the version and sequence.
	u[6] = 0x70 | byte(seq>>8)
	u[7] = byte(seq)

	// Fill bytes 8 to 15 with random data.
	if _, err := io.ReadFull(rand.Reader, u[8:]); err != nil {
		panic(fmt.Errorf("uuid: failed to read random bytes: %w", err))
	}

	// Set byte 8 to the variant.
	u[8] = (u[8] & 0x3f) | 0x80

	return u
}

// Parse parses a standard 36-character hyphenated string representation of a
// UUID into a UUIDv7 type.
//
// It strictly validates that the UUID is Version 7 and Variant 1 (RFC 4122).
func Parse(s string) (UUIDv7, error) {
	var u UUIDv7
	if len(s) != 36 {
		return u, fmt.Errorf("invalid UUID length (%d)", len(s))
	}
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return u, fmt.Errorf("invalid UUID format")
	}
	h := s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:]
	if _, err := hex.Decode(u[:], []byte(h)); err != nil {
		return u, fmt.Errorf("invalid UUID characters: %w", err)
	}
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
	mu   sync.Mutex
	last int64
)

// count implements Method 3 from the UUIDv7 specification (RFC 9562, Section
// 6.2). It returns a timestamp (ms) and a strictly increasing sequence (seq).
//
// The sequence holds fractional nanoseconds scaled to fit into 12 bits.
func count() (ms, seq int64) {
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
	// This allows us to handle time rollbacks or high-frequency generation
	// using simple integer arithmetic.
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
