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

package xxh3

import (
	"encoding/binary"
	"errors"
)

// Hash returns the 64-bit xxHash3 checksum of byte slice b using the default
// 192-byte secret key.
//
// It operates with zero heap allocations across all input lengths and is
// optimized for high throughput.
func Hash(b []byte) uint64 {
	return HashSecret(b, defaultSecret[:])
}

// HashSeed returns the 64-bit xxHash3 checksum of byte slice b using a 64-bit
// seed value.
//
// When seed is 0, this function is identical to [Hash]. When seed is non-zero,
// a 192-byte custom secret key is derived on the stack from the default secret
// and seed value.
func HashSeed(b []byte, seed uint64) uint64 {
	if seed == 0 {
		return HashSecret(b, defaultSecret[:])
	}
	var cSec [secDefSize]byte
	initSec(defaultSecret[:], seed, cSec[:])
	return hash64(b, cSec[:], seed)
}

// HashSecret returns the 64-bit xxHash3 checksum of byte slice b using a
// custom secret key buffer.
//
// The secret slice must contain at least 136 bytes. Passing a secret shorter
// than 136 bytes will cause a panic.
func HashSecret(b, sec []byte) uint64 {
	if len(sec) < secMinSize {
		panic("secret size must be at least 136 bytes")
	}
	return hash64(b, sec, 0)
}

// HashString returns the 64-bit xxHash3 checksum of string s using the
// default 192-byte secret key.
//
// It converts s to a byte slice using unsafe operations to guarantee zero heap
// allocations.
func HashString(s string) uint64 {
	return Hash(strToBytes(s))
}

// HashStringSeed returns the 64-bit xxHash3 checksum of string s using a
// 64-bit seed value.
func HashStringSeed(s string, seed uint64) uint64 {
	return HashSeed(strToBytes(s), seed)
}

// HashStringSecret returns the 64-bit xxHash3 checksum of string s using a
// custom secret key buffer.
func HashStringSecret(s string, sec []byte) uint64 {
	return HashSecret(strToBytes(s), sec)
}

// Hasher implements 64-bit streaming XXH3 hashing.
//
// It satisfies [hash.Hash64], [hash.Hash], [io.Writer], [io.StringWriter],
// [encoding.BinaryMarshaler], and [encoding.BinaryUnmarshaler].
type Hasher struct {
	acc      [8]uint64
	secret   []byte
	seed     uint64
	buf      [blockLen]byte
	bufLen   int
	totalLen uint64
	cSec     [secDefSize]byte
	buffered bool
}

// New returns a new Hasher initialized with the default 192-byte secret key.
func New() *Hasher {
	return NewSeed(0)
}

// NewSeed returns a new Hasher initialized with a 64-bit seed value.
func NewSeed(seed uint64) *Hasher {
	h := &Hasher{seed: seed}
	if seed == 0 {
		h.secret = defaultSecret[:]
	} else {
		initSec(defaultSecret[:], seed, h.cSec[:])
		h.secret = h.cSec[:]
	}
	h.Reset()
	return h
}

// NewSecret returns a new Hasher initialized with a custom secret key buffer.
//
// The secret slice must contain at least 136 bytes. Passing a secret shorter
// than 136 bytes will cause a panic.
func NewSecret(sec []byte) *Hasher {
	if len(sec) < secMinSize {
		panic("secret size must be at least 136 bytes")
	}
	h := &Hasher{secret: sec}
	h.Reset()
	return h
}

// Reset resets the state of the Hasher, clearing internal buffers and
// accumulators to prepare it for processing a new stream.
func (h *Hasher) Reset() {
	initAcc(&h.acc)
	h.bufLen = 0
	h.totalLen = 0
	h.buffered = false
}

// Size returns 8, representing the 8-byte (64-bit) size of the hash digest.
func (h *Hasher) Size() int {
	return 8
}

// BlockSize returns 64, representing the internal stripe block size in bytes.
func (h *Hasher) BlockSize() int {
	return stripeLen
}

// Write appends p to the running hash state.
//
// It returns the number of bytes written and a nil error.
func (h *Hasher) Write(p []byte) (int, error) {
	n := len(p)
	h.totalLen += uint64(n)

	if h.bufLen+n <= blockLen {
		copy(h.buf[h.bufLen:], p)
		h.bufLen += n
		return n, nil
	}

	if h.bufLen > 0 {
		cp := copy(h.buf[h.bufLen:], p)
		h.bufLen += cp
		p = p[cp:]

		if h.bufLen == blockLen {
			accumulate(&h.acc, h.buf[:], h.secret)
			h.bufLen = 0
			h.buffered = true
		}
	}

	for len(p) >= blockLen {
		accumulate(&h.acc, p[:blockLen], h.secret)
		p = p[blockLen:]
		h.buffered = true
	}

	if len(p) > 0 {
		copy(h.buf[0:], p)
		h.bufLen = len(p)
	}

	return n, nil
}

// WriteString appends string s to the running hash state without heap
// allocations.
func (h *Hasher) WriteString(s string) (int, error) {
	return h.Write(strToBytes(s))
}

// Sum64 returns the 64-bit xxHash3 digest of all data written so far.
func (h *Hasher) Sum64() uint64 {
	if !h.buffered && h.totalLen <= midSizeMax {
		if h.seed != 0 {
			return hash64(h.buf[:h.bufLen], h.secret, h.seed)
		}
		return HashSecret(h.buf[:h.bufLen], h.secret)
	}

	accCopy := h.acc
	if h.bufLen > 0 {
		accumulate(&accCopy, h.buf[:h.bufLen], h.secret)
	}
	return mergeAcc(&accCopy, h.secret, h.totalLen)
}

// Sum appends the 8-byte little-endian 64-bit checksum of the written data to
// in and returns the updated slice.
func (h *Hasher) Sum(in []byte) []byte {
	s := h.Sum64()
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], s)
	return append(in, b[:]...)
}

const marshalHdr = "xxh3_v1"

// MarshalBinary serializes the Hasher state into a byte slice.
func (h *Hasher) MarshalBinary() ([]byte, error) {
	b := make([]byte, 7+64+8+8+4+1+h.bufLen)
	copy(b[0:7], marshalHdr)
	off := 7
	for i := range 8 {
		binary.LittleEndian.PutUint64(b[off:off+8], h.acc[i])
		off += 8
	}
	binary.LittleEndian.PutUint64(b[off:off+8], h.seed)
	off += 8
	binary.LittleEndian.PutUint64(b[off:off+8], h.totalLen)
	off += 8
	binary.LittleEndian.PutUint32(b[off:off+4], uint32(h.bufLen))
	off += 4
	if h.buffered {
		b[off] = 1
	} else {
		b[off] = 0
	}
	off++
	copy(b[off:], h.buf[:h.bufLen])
	return b, nil
}

// UnmarshalBinary restores the Hasher state from data.
func (h *Hasher) UnmarshalBinary(data []byte) error {
	if len(data) < 7+64+8+8+4+1 {
		return errors.New("invalid binary state length")
	}
	if string(data[0:7]) != marshalHdr {
		return errors.New("incompatible binary state header")
	}
	off := 7
	for i := range 8 {
		h.acc[i] = binary.LittleEndian.Uint64(data[off : off+8])
		off += 8
	}
	h.seed = binary.LittleEndian.Uint64(data[off : off+8])
	off += 8
	h.totalLen = binary.LittleEndian.Uint64(data[off : off+8])
	off += 8
	bLen := int(binary.LittleEndian.Uint32(data[off : off+4]))
	off += 4
	if bLen > blockLen || len(data) < off+bLen {
		return errors.New("corrupted binary state buffer size")
	}
	h.buffered = data[off] != 0
	off++
	h.bufLen = bLen
	copy(h.buf[:bLen], data[off:off+bLen])

	if h.seed == 0 {
		h.secret = defaultSecret[:]
	} else {
		initSec(defaultSecret[:], h.seed, h.cSec[:])
		h.secret = h.cSec[:]
	}

	return nil
}
