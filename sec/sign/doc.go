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

// Package sign bridges the gap between Go's standard [crypto.Signer] and
// context-aware operations. It provides a [Signer] interface that respects
// context cancellation and deadlines during cryptographic operations.
//
// # Usage
//
// The package offers utilities for adapting standard signers and parsing keys:
//
//   - [From]: Wraps a standard [crypto.Signer] into a context-aware [Signer].
//   - [To]: Unwraps or adapts a [Signer] back to a standard [crypto.Signer]
//     with a baked-in context.
//   - [Decode]: Parses PEM-encoded private keys (PKCS8, EC, PKCS1) into a
//     ready-to-use [Signer].
//   - [Encode]: Serializes private keys back into PKCS8 PEM format.
//
// PKCS8 covers all standard library key types, including post-quantum
// ML-DSA seed keys ([*crypto/mldsa.PrivateKey]) as of Go 1.27.
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//
//	signer, err := sign.Decode(pemData)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	sig, err := signer.Sign(ctx, rand.Reader, digest, nil)
package sign
