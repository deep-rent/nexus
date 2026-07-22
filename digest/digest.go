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

package digest

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"hash"
)

// Algorithm constructs a fresh [hash.Hash]. It is the injection point of the
// package: production code uses [DefaultAlgorithm] (SHA-256), while callers may
// substitute any other algorithm — SHA-512, SHA-3, BLAKE2 — or a keyed
// construction such as HMAC:
//
//	key := []byte("...")
//	h := digest.New(func() hash.Hash { return hmac.New(sha256.New, key) })
//
// A [Hasher] calls its Algorithm afresh for every fingerprint, so any Algorithm
// that returns an independent hash per call (as the standard-library
// constructors do) yields a Hasher that is safe for concurrent use.
type Algorithm = func() hash.Hash

// DefaultAlgorithm is SHA-256, a 256-bit cryptographic hash suitable for
// fingerprinting secrets and detecting tampering. Its digests encode to 43
// base64url characters.
var DefaultAlgorithm Algorithm = sha256.New

// Hasher computes fingerprints of values using a configurable [Algorithm]. It
// is safe for concurrent use provided its Algorithm is (see [Algorithm]).
//
// A fingerprint is the hash sum of the input encoded as an unpadded base64url
// string, making it safe for inclusion in URLs, HTTP headers, JSON payloads,
// and database columns. Fingerprints let a raw secret be stored or compared by
// its hash rather than in the clear.
type Hasher struct {
	algorithm Algorithm
}

// New returns a [Hasher] that fingerprints values with the given [Algorithm].
// If algorithm is nil, [DefaultAlgorithm] (SHA-256) is used.
func New(algorithm Algorithm) *Hasher {
	if algorithm == nil {
		algorithm = DefaultAlgorithm
	}
	return &Hasher{algorithm: algorithm}
}

// Bytes returns the fingerprint of value: its hash sum encoded as an unpadded
// base64url string. With the default SHA-256 algorithm the result is 43
// characters long.
func (h *Hasher) Bytes(value []byte) string {
	sum := h.algorithm()
	// This call is documented never to return an error.
	_, _ = sum.Write(value)
	return base64.RawURLEncoding.EncodeToString(sum.Sum(nil))
}

// String returns the fingerprint of value. It is shorthand for hashing the
// bytes of a string; see [Hasher.Bytes].
func (h *Hasher) String(value string) string {
	return h.Bytes([]byte(value))
}

// Match reports whether value fingerprints to digest under this hasher. It
// hashes value with [Hasher.String] and compares the result against digest in
// constant time via [Equal].
//
// Match is the verification counterpart to String: fingerprint a secret once
// and store it, then check a candidate with Match rather than comparing digests
// with ==, which compares in variable time and leaks how much matched.
func (h *Hasher) Match(value, digest string) bool {
	return Equal(h.String(value), digest)
}

// DefaultHasher fingerprints values with [DefaultAlgorithm]. It is a
// ready-to-use replacement for one-off fingerprinting.
var DefaultHasher = New(DefaultAlgorithm)

// Equal reports whether two digest strings are identical, comparing them in
// constant time via [subtle.ConstantTimeCompare] to avoid leaking their
// contents through timing side channels.
//
// The comparison is only meaningful for digests produced by the same
// [Algorithm]; digests of different lengths are never equal.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
