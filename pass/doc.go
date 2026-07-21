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

// Package pass implements password hashing and verification.
//
// Passwords are hashed into self-describing [Record] values that carry the
// algorithm name alongside all parameters needed for verification
// (iteration count, salt, and digest). Records serialize to a compact JSON
// object suitable for a database column, and verification resolves the
// algorithm dynamically from the stored record. This makes parameter
// upgrades and algorithm migrations routine: old records keep verifying
// with the parameters they were created with, while new records pick up
// the current configuration; see [Hasher.Outdated] for detecting hashes
// that should be upgraded.
//
// # Usage
//
// Create a [Hasher] once at startup and share it; it is safe for
// concurrent use.
//
//	hasher := pass.New()
//
//	// Registration: store the JSON record.
//	record, err := hasher.Hash("s3cret")
//	// e.g. {"alg":"pbkdf2-sha256","iter":600000,"salt":"...","digest":"..."}
//
//	// Login: verify the password against the stored record.
//	ok, err := hasher.Verify(record, "s3cret")
//
//	// After a successful login, transparently upgrade stale hashes.
//	if stale, _ := hasher.Outdated(record); stale {
//	  record, _ = hasher.Hash("s3cret")
//	  // ... persist the new record
//	}
//
// Custom schemes (e.g., a legacy bcrypt wrapper during a migration)
// implement [Algorithm] and are registered under their record name via
// [WithAlgorithm]; [WithDefault] additionally selects the algorithm used
// for new hashes.
//
// # FIPS 140 compliance
//
// The default algorithms are PBKDF2-HMAC-SHA256 and PBKDF2-HMAC-SHA512,
// the password-based key derivation approved by NIST SP 800-132. They are
// built on [crypto/pbkdf2] from the Go standard library, which is served
// by the Go Cryptographic Module when the toolchain runs in FIPS 140-3
// mode (GOFIPS140); the package defaults — 128-bit salts and digests of
// the full hash size — satisfy the module's FIPS-only constraints. Note
// that overall FIPS compliance is a property of the build and deployment,
// not of this package alone.
//
// # Storage
//
// Records marshal to JSON with binary fields encoded as base64:
//
//	{"alg":"pbkdf2-sha256","iter":600000,"salt":"...","digest":"..."}
//
// Store them in a text or JSON column sized generously (256 bytes fits
// the defaults comfortably). Treat records as opaque: rewriting or
// truncating them invalidates the password.
package pass
