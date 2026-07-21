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

package pass

import (
	"encoding/json/v2"
	"errors"
	"fmt"
)

var (
	// ErrUnknownAlgorithm is returned when a record names an algorithm
	// that has not been registered with the [Hasher].
	ErrUnknownAlgorithm = errors.New("unknown hashing algorithm")
	// ErrMalformedRecord is returned when a record cannot be parsed or
	// misses required parameters.
	ErrMalformedRecord = errors.New("malformed password record")
)

// Record is the self-describing result of hashing a password. It carries
// the algorithm name and every parameter verification needs, so that
// stored hashes remain verifiable after the server's configuration
// changes.
type Record struct {
	// Algorithm names the hashing scheme that produced this record. It is
	// the key under which [Hasher] resolves the [Algorithm] during
	// verification.
	Algorithm string `json:"alg"`
	// Iterations is the work factor the digest was derived with. Its exact
	// meaning is algorithm-specific; for the PBKDF2 family it is the
	// iteration count.
	Iterations int `json:"iter,omitzero"`
	// Salt is the random per-password salt. It thwarts precomputed lookup
	// tables and makes equal passwords hash differently.
	Salt []byte `json:"salt,omitzero"`
	// Digest is the derived key that verification compares against.
	Digest []byte `json:"digest"`
}

// Algorithm defines the contract for a password hashing scheme.
//
// Implementations must be safe for concurrent use. The [Hasher] dispatches
// verification to the implementation registered under the name stored in
// the record, so implementations must accept any record they ever
// produced, including those created with older parameters.
type Algorithm interface {
	// Name returns the unique identifier written into records produced by
	// this algorithm.
	Name() string
	// Hash derives a fresh [Record] from the plaintext password using the
	// algorithm's current parameters.
	Hash(password string) (Record, error)
	// Verify reports whether the password matches the record. A mismatch
	// is (false, nil); an error is returned only if the record is
	// malformed or the derivation fails.
	//
	// Implementations must compare digests in constant time.
	Verify(record Record, password string) (bool, error)
	// Outdated reports whether the record was produced with parameters
	// weaker than the algorithm's current configuration and should be
	// rehashed.
	Outdated(record Record) bool
}

// Hasher hashes passwords with a default [Algorithm] and verifies them
// against any registered one, resolved dynamically from the stored record.
//
// Create instances with [New]. A Hasher is immutable after construction
// and safe for concurrent use.
type Hasher struct {
	def        Algorithm
	algorithms map[string]Algorithm
}

// Option customizes a [Hasher] during construction with [New].
type Option func(*Hasher)

// WithAlgorithm registers an [Algorithm] for verification under its name.
// Records naming the algorithm verify against it; new hashes are not
// affected. Registering a second algorithm with the same name replaces the
// first.
//
// It panics if the algorithm is nil or unnamed, since both are startup
// configuration errors.
func WithAlgorithm(alg Algorithm) Option {
	return func(h *Hasher) { h.register(alg) }
}

// WithDefault registers an [Algorithm] like [WithAlgorithm] and
// additionally selects it for hashing new passwords.
//
// It panics if the algorithm is nil or unnamed, since both are startup
// configuration errors.
func WithDefault(alg Algorithm) Option {
	return func(h *Hasher) {
		h.register(alg)
		h.def = alg
	}
}

// register adds the algorithm to the verification registry.
func (h *Hasher) register(alg Algorithm) {
	if alg == nil {
		panic("algorithm is required")
	}
	if alg.Name() == "" {
		panic("algorithm name is required")
	}
	h.algorithms[alg.Name()] = alg
}

// New assembles a [Hasher] from the given options.
//
// By default, new passwords are hashed with PBKDF2-HMAC-SHA256, and both
// [PBKDF2SHA256] and [PBKDF2SHA512] are registered for verification with
// their default parameters. Use [WithDefault] to hash with a different
// algorithm, and [WithAlgorithm] to register additional ones for
// verification; the built-in registrations always remain available as a
// verification fallback unless replaced by name.
func New(opts ...Option) *Hasher {
	h := &Hasher{algorithms: make(map[string]Algorithm)}

	def := PBKDF2SHA256(0)
	h.register(def)
	h.register(PBKDF2SHA512(0))
	h.def = def

	for _, opt := range opts {
		opt(h)
	}

	return h
}

// Hash derives a fresh hash of the password using the default algorithm
// and returns it as a JSON-encoded [Record] for storage.
func (h *Hasher) Hash(password string) ([]byte, error) {
	rec, err := h.def.Hash(password)
	if err != nil {
		return nil, err
	}
	return json.Marshal(rec)
}

// Verify reports whether the password matches the stored JSON-encoded
// [Record].
//
// The hashing scheme is resolved dynamically from the record's algorithm
// name, so records produced under older configurations keep verifying. A
// mismatch is (false, nil); an error is returned only if the record is
// malformed ([ErrMalformedRecord]), names an unregistered algorithm
// ([ErrUnknownAlgorithm]), or the derivation itself fails.
func (h *Hasher) Verify(record []byte, password string) (bool, error) {
	rec, err := h.parse(record)
	if err != nil {
		return false, err
	}

	alg, ok := h.algorithms[rec.Algorithm]
	if !ok {
		return false, fmt.Errorf(
			"%w: %q",
			ErrUnknownAlgorithm,
			rec.Algorithm,
		)
	}

	return alg.Verify(rec, password)
}

// Outdated reports whether the stored JSON-encoded [Record] should be
// rehashed: either it was produced by an algorithm other than the current
// default, or the default algorithm considers its parameters weaker than
// the current configuration.
//
// Call it after a successful verification, while the plaintext password is
// at hand, and store a fresh [Hasher.Hash] when it reports true. This
// keeps stored hashes converging to the strongest configuration without a
// mass reset.
func (h *Hasher) Outdated(record []byte) (bool, error) {
	rec, err := h.parse(record)
	if err != nil {
		return false, err
	}
	if rec.Algorithm != h.def.Name() {
		return true, nil
	}
	return h.def.Outdated(rec), nil
}

// parse decodes a stored record and checks the fields the [Hasher] itself
// depends on.
func (h *Hasher) parse(record []byte) (Record, error) {
	var rec Record
	if err := json.Unmarshal(record, &rec); err != nil {
		return rec, fmt.Errorf("%w: %w", ErrMalformedRecord, err)
	}
	if rec.Algorithm == "" {
		return rec, fmt.Errorf("%w: missing algorithm", ErrMalformedRecord)
	}
	return rec, nil
}
