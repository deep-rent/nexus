// Package uuid provides an implementation of Version 7 (Time-ordered) Universally
// Unique Identifiers (UUID) as defined in RFC 9562.
package uuid

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
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

// New generates a time-ordered UUIDv7.
//
// It fills the first 48 bits with the current Unix timestamp (ms) and the
// remaining bits with cryptographically secure random data.
//
// Note: This implementation does not guarantee strict monotonicity for UUIDs
// generated within the exact same millisecond; it relies on random entropy
// for collision avoidance in that sub-millisecond window.
func New() UUIDv7 {
	var u UUIDv7

	// 1. Get current timestamp in milliseconds (48 bits)
	t := uint64(time.Now().UnixMilli())

	// 2. Fill the first 6 bytes (48 bits) with the timestamp (Big Endian)
	u[0] = byte(t >> 40)
	u[1] = byte(t >> 32)
	u[2] = byte(t >> 24)
	u[3] = byte(t >> 16)
	u[4] = byte(t >> 8)
	u[5] = byte(t)

	// 3. Fill the remaining 10 bytes with random data
	if _, err := io.ReadFull(rand.Reader, u[6:]); err != nil {
		panic(fmt.Errorf("uuid: failed to read random bytes: %w", err))
	}

	// 4. Set Version (7)
	// The high 4 bits of byte 6 must be 0111 (0x70)
	u[6] = (u[6] & 0x0f) | 0x70

	// 5. Set Variant (RFC 4122)
	// The high 2 bits of byte 8 must be 10 (0x80)
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
		return UUIDv7{}, fmt.Errorf(
			"uuid: invalid version: expected v7, got v%d", u[6]>>4,
		)
	}

	if (u[8] & 0xc0) != 0x80 {
		return UUIDv7{}, fmt.Errorf(
			"uuid: invalid variant: expected RFC 4122",
		)
	}

	return u, nil
}
