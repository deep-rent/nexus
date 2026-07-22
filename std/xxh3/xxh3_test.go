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
	"math/rand"
	"testing"
)

// TestBasicInvariants verifies that empty inputs, nil byte slices, and empty
// strings produce identical hash values.
func TestBasicInvariants(t *testing.T) {
	h0 := Hash(nil)
	h0b := Hash([]byte{})
	h0s := HashString("")
	if h0 != h0b || h0 != h0s {
		t.Errorf("Hash(nil) = %x, Hash([]byte{}) = %x, HashString(\"\") = %x; "+
			"want all equal", h0, h0b, h0s)
	}
}

// TestStringConsistency verifies that string hash functions match byte slice
// hash functions across different length payloads.
func TestStringConsistency(t *testing.T) {
	tests := []string{
		"",
		"a",
		"ab",
		"abc",
		"hello world",
		"The quick brown fox jumps over the lazy dog",
		"a long string that spans multiple 64-byte stripes in xxHash3 " +
			"algorithm processing loop",
	}

	for _, s := range tests {
		b := []byte(s)
		if h1, h2 := Hash(b), HashString(s); h1 != h2 {
			t.Errorf("Hash vs HashString mismatch for %q: %x vs %x", s, h1, h2)
		}
		if h1, h2 := HashSeed(b, 42), HashStringSeed(s, 42); h1 != h2 {
			t.Errorf("HashSeed vs HashStringSeed mismatch for %q: %x vs %x",
				s, h1, h2)
		}
		if h1, h2 := HashSecret(b, defaultSecret[:]),
			HashStringSecret(s, defaultSecret[:]); h1 != h2 {
			t.Errorf("HashSecret vs HashStringSecret mismatch for %q: %x vs %x",
				s, h1, h2)
		}
	}
}

// TestStreamingConsistency verifies that Hasher streaming produces identical
// hash outputs to one-shot Hash functions across small and large chunk sizes.
func TestStreamingConsistency(t *testing.T) {
	sizes := []int{
		0, 1, 3, 4, 8, 9, 16, 17, 32, 64, 128, 129, 240, 241, 512, 1024,
		2048, 4096, 10000,
	}
	rng := rand.New(rand.NewSource(12345))

	for _, sz := range sizes {
		data := make([]byte, sz)
		rng.Read(data)

		exp := Hash(data)

		// Test single write
		h := New()
		h.Write(data)
		if got := h.Sum64(); got != exp {
			t.Errorf("Hasher.Sum64() for size %d = %x; want %x",
				sz, got, exp)
		}

		// Test chunked writes (small chunks)
		h.Reset()
		chkSize := 7
		for i := 0; i < len(data); i += chkSize {
			end := min(i+chkSize, len(data))
			h.Write(data[i:end])
		}
		if got := h.Sum64(); got != exp {
			t.Errorf("Chunked Hasher.Sum64() for size %d = %x; want %x",
				sz, got, exp)
		}
	}
}

// TestSeededStreaming verifies that seeded streaming hash calculations match
// one-shot seeded hash outputs.
func TestSeededStreaming(t *testing.T) {
	seed := uint64(0xdeadbeef12345678)
	data := []byte("Testing seeded streaming hash consistency across " +
		"multiple chunk boundaries!")

	exp := HashSeed(data, seed)

	h := NewSeed(seed)
	h.Write(data[:10])
	h.Write(data[10:30])
	h.Write(data[30:])

	if got := h.Sum64(); got != exp {
		t.Errorf("Seeded Hasher.Sum64() = %x; want %x", got, exp)
	}
}

// TestMarshalUnmarshalBinary verifies state serialization and recovery for
// streaming Hasher states.
func TestMarshalUnmarshalBinary(t *testing.T) {
	data := []byte("A long stream of test data to verify binary " +
		"marshaling of XXH3 Hasher state across multiple chunk writes.")

	h1 := NewSeed(0x12345678)
	h1.Write(data[:40])

	st, err := h1.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	h2 := New()
	if err := h2.UnmarshalBinary(st); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	h1.Write(data[40:])
	h2.Write(data[40:])

	if got1, got2 := h1.Sum64(), h2.Sum64(); got1 != got2 {
		t.Errorf("Sum64 mismatch after UnmarshalBinary: %x vs %x", got1, got2)
	}
}

// TestShortSecretPanics verifies that custom secret keys shorter than 136 bytes
// cause a panic as required by xxHash3 algorithm specifications.
func TestShortSecretPanics(t *testing.T) {
	shortSec := make([]byte, 100)
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("HashSecret with short secret did not panic")
		}
	}()
	HashSecret([]byte("test"), shortSec)
}
