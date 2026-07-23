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

// Package digest computes cryptographic fingerprints of values and compares
// them in constant time.
//
// # Abstractions
//
// The hash function is the single injection point of the package, expressed as
// an [Algorithm]. Production code relies on [DefaultAlgorithm]; callers may
// substitute SHA-512, SHA-3, BLAKE2, or a keyed construction such as HMAC. A
// [Hasher] binds an Algorithm and turns values into fingerprints — the hash sum
// encoded as an unpadded base64url string. Hashers are configured once and are
// safe for concurrent use.
//
// # Usage
//
// Fingerprint a value with the default SHA-256 hasher (43 base64url
// characters):
//
//	fp := digest.DefaultHasher.String("raw-bearer-token")
//
// Bind a different algorithm, for example a keyed HMAC:
//
//	key := []byte("...")
//	h := digest.New(func() hash.Hash { return hmac.New(sha256.New, key) })
//	fp := h.String("raw-bearer-token")
//
// Compare two digest strings in constant time:
//
//	if digest.Equal(d1, d2) {
//		// Digests match.
//	}
package digest
