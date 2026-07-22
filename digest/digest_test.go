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

package digest_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
	"sync"
	"testing"

	"github.com/deep-rent/nexus/digest"
)

// b64 encodes a raw hash sum the way the package does, so tests can assert the
// exact fingerprint independently of the implementation.
func b64(sum []byte) string {
	return base64.RawURLEncoding.EncodeToString(sum)
}

func TestDefaultHasher(t *testing.T) {
	t.Parallel()

	const input = "secret-auth-token-12345"
	got := digest.DefaultHasher.String(input)

	sum := sha256.Sum256([]byte(input))
	if want := b64(sum[:]); got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
	// SHA-256 is 32 bytes, which is 43 unpadded base64url characters.
	if exp, act := 43, len(got); exp != act {
		t.Fatalf("expected %d chars, got %d", exp, act)
	}
}

func TestBytesAndStringAgree(t *testing.T) {
	t.Parallel()

	h := digest.New(nil)
	const input = "secret-auth-token-12345"
	if s, b := h.String(input), h.Bytes([]byte(input)); s != b {
		t.Fatalf("String and Bytes disagree: %s vs %s", s, b)
	}
}

func TestNewNilUsesDefaultAlgorithm(t *testing.T) {
	t.Parallel()

	const input = "raw-bearer-token"
	if got, want := digest.New(nil).String(input),
		digest.DefaultHasher.String(input); got != want {
		t.Fatalf("nil algorithm should equal DefaultHasher: %s vs %s", got, want)
	}
}

// TestInjectableAlgorithm confirms the hasher fingerprints with whatever
// algorithm is injected, not a hardcoded one.
func TestInjectableAlgorithm(t *testing.T) {
	t.Parallel()

	const input = "raw-bearer-token"

	sum256 := sha256.Sum256([]byte(input))
	sum512 := sha512.Sum512([]byte(input))

	tests := []struct {
		name string
		algo digest.Algorithm
		want string
		size int
	}{
		{"sha256", sha256.New, b64(sum256[:]), 43},
		{"sha512", sha512.New, b64(sum512[:]), 86},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := digest.New(tt.algo).String(input)
			if got != tt.want {
				t.Fatalf("expected %s, got %s", tt.want, got)
			}
			if len(got) != tt.size {
				t.Fatalf("expected %d chars, got %d", tt.size, len(got))
			}
		})
	}
}

// TestKeyedAlgorithm confirms a keyed HMAC construction can be injected.
func TestKeyedAlgorithm(t *testing.T) {
	t.Parallel()

	key := []byte("signing-key")
	const input = "raw-bearer-token"

	h := digest.New(func() hash.Hash { return hmac.New(sha256.New, key) })
	got := h.String(input)

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(input))
	if want := b64(mac.Sum(nil)); got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

// TestAlgorithmInvokedPerCall verifies a fresh hash is constructed for every
// fingerprint, the property that makes a [digest.Hasher] concurrency-safe.
func TestAlgorithmInvokedPerCall(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	calls := 0
	h := digest.New(func() hash.Hash {
		mu.Lock()
		calls++
		mu.Unlock()
		return sha256.New()
	})

	h.String("a")
	h.Bytes([]byte("b"))

	if calls != 2 {
		t.Fatalf("expected algorithm invoked 2 times, got %d", calls)
	}
}

func TestEqual(t *testing.T) {
	t.Parallel()

	h := digest.New(nil)
	a := h.String("token-A")
	b := h.String("token-B")

	tests := []struct {
		name string
		x, y string
		want bool
	}{
		{"identical", a, a, true},
		{"different", a, b, false},
		{"different length", a, a + "x", false},
		{"both empty", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := digest.Equal(tt.x, tt.y); got != tt.want {
				t.Fatalf("Equal(%q, %q) = %v, want %v", tt.x, tt.y, got, tt.want)
			}
		})
	}
}

// TestHasherConcurrent exercises a single hasher from many goroutines; run with
// -race, it guards the concurrency-safety claim.
func TestHasherConcurrent(t *testing.T) {
	t.Parallel()

	h := digest.New(nil)
	const input = "raw-bearer-token"
	want := h.String(input)

	const goroutines = 64
	var wg sync.WaitGroup
	bad := make(chan string, goroutines)
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := h.String(input); got != want {
				bad <- got
			}
		}()
	}
	wg.Wait()
	close(bad)

	if got, ok := <-bad; ok {
		t.Fatalf("concurrent digest mismatch: got %s, want %s", got, want)
	}
}
