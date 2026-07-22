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
	"cmp"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"hash"
)

const (
	// AlgorithmPBKDF2SHA256 is the record name of the PBKDF2-HMAC-SHA256
	// algorithm.
	AlgorithmPBKDF2SHA256 = "pbkdf2-sha256"
	// AlgorithmPBKDF2SHA512 is the record name of the PBKDF2-HMAC-SHA512
	// algorithm.
	AlgorithmPBKDF2SHA512 = "pbkdf2-sha512"
)

const (
	// DefaultSHA256Iterations is the default iteration count for
	// PBKDF2-HMAC-SHA256, following the OWASP Password Storage Cheat Sheet
	// recommendation.
	DefaultSHA256Iterations = 600_000
	// DefaultSHA512Iterations is the default iteration count for
	// PBKDF2-HMAC-SHA512. It is lower than the SHA-256 default because a
	// single SHA-512 iteration costs roughly three times as much, yielding
	// comparable attack resistance per hash.
	DefaultSHA512Iterations = 210_000
)

// saltLength is the size of generated salts in bytes. 128 bits is the
// minimum required by NIST SP 800-132 and enforced by the Go Cryptographic
// Module in FIPS 140-only mode.
const saltLength = 16

// minDigestLength is the smallest digest accepted during verification.
// Records with shorter digests are rejected as malformed rather than
// verified, so a truncated database value cannot degrade into an easily
// forgeable comparison. 112 bits is the FIPS 140 floor for key lengths.
const minDigestLength = 14

// pbkdf2Algorithm implements the [Algorithm] interface using PBKDF2-HMAC
// with a configurable hash function.
type pbkdf2Algorithm struct {
	name       string
	hash       func() hash.Hash
	iterations int
	keyLength  int
}

var _ Algorithm = (*pbkdf2Algorithm)(nil)

// PBKDF2SHA256 returns the PBKDF2-HMAC-SHA256 [Algorithm], deriving
// 256-bit digests from 128-bit random salts.
//
// The iteration count applies to newly hashed passwords; verification
// always uses the count stored in the record. A count of zero selects
// [DefaultSHA256Iterations]; negative counts panic, since the work factor
// is startup configuration.
func PBKDF2SHA256(iterations int) Algorithm {
	return newPBKDF2(
		AlgorithmPBKDF2SHA256,
		sha256.New,
		sha256.Size,
		iterations,
		DefaultSHA256Iterations,
	)
}

// PBKDF2SHA512 returns the PBKDF2-HMAC-SHA512 [Algorithm], deriving
// 512-bit digests from 128-bit random salts.
//
// The iteration count applies to newly hashed passwords; verification
// always uses the count stored in the record. A count of zero selects
// [DefaultSHA512Iterations]; negative counts panic, since the work factor
// is startup configuration.
func PBKDF2SHA512(iterations int) Algorithm {
	return newPBKDF2(
		AlgorithmPBKDF2SHA512,
		sha512.New,
		sha512.Size,
		iterations,
		DefaultSHA512Iterations,
	)
}

// newPBKDF2 assembles a PBKDF2 variant with the given defaults.
func newPBKDF2(
	name string,
	hash func() hash.Hash,
	keyLength int,
	iterations, fallback int,
) Algorithm {
	if iterations < 0 {
		panic("iteration count must not be negative")
	}
	return &pbkdf2Algorithm{
		name:       name,
		hash:       hash,
		iterations: cmp.Or(iterations, fallback),
		keyLength:  keyLength,
	}
}

// Name implements the [Algorithm] interface.
func (a *pbkdf2Algorithm) Name() string { return a.name }

// Hash implements the [Algorithm] interface.
func (a *pbkdf2Algorithm) Hash(password string) (Record, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return Record{}, fmt.Errorf("failed to generate salt: %w", err)
	}

	digest, err := pbkdf2.Key(
		a.hash,
		password,
		salt,
		a.iterations,
		a.keyLength,
	)
	if err != nil {
		return Record{}, fmt.Errorf("failed to derive digest: %w", err)
	}

	return Record{
		Algorithm:  a.name,
		Iterations: a.iterations,
		Salt:       salt,
		Digest:     digest,
	}, nil
}

// Verify implements the [Algorithm] interface. It derives the digest with
// the parameters stored in the record — not the current configuration — so
// records produced under older settings keep verifying.
func (a *pbkdf2Algorithm) Verify(rec Record, password string) (bool, error) {
	switch {
	case rec.Iterations < 1:
		return false, fmt.Errorf(
			"%w: invalid iteration count",
			ErrMalformedRecord,
		)
	case len(rec.Salt) == 0:
		return false, fmt.Errorf("%w: missing salt", ErrMalformedRecord)
	case len(rec.Digest) < minDigestLength:
		return false, fmt.Errorf(
			"%w: digest too short",
			ErrMalformedRecord,
		)
	}

	digest, err := pbkdf2.Key(
		a.hash,
		password,
		rec.Salt,
		rec.Iterations,
		len(rec.Digest),
	)
	if err != nil {
		return false, fmt.Errorf("failed to derive digest: %w", err)
	}

	return subtle.ConstantTimeCompare(digest, rec.Digest) == 1, nil
}

// Outdated implements the [Algorithm] interface. A record is outdated if
// it was derived with fewer iterations than currently configured, or if
// its digest length differs from the full hash size.
func (a *pbkdf2Algorithm) Outdated(rec Record) bool {
	return rec.Iterations < a.iterations || len(rec.Digest) != a.keyLength
}
