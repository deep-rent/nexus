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

// Package jwk provides functionality to parse, manage, and marshal JSON Web
// Keys (JWK) and JSON Web Key Sets (JWKS), as defined in RFC 7517.
//
// # Verification
//
// The package is primarily designed to consume public keys from a remote JWKS
// endpoint for the purpose of verifying JWT signatures.
//
// # Signing
//
// While JWKS parsing focuses on public keys, this package also supports the
// creation of signing keys via [NewKeyPair]. These keys wrap a
// [crypto.Signer] (e.g., hardware modules, KMS, or standard library keys) to
// support token issuance operations.
//
// # Encoding
//
// The package supports serializing keys back to JSON. This is useful for
// services that need to expose their own public keys via a JWKS endpoint or
// for persisting key sets. The marshaling logic is strict: it only outputs
// public key material and adheres to RFC 7518 fixed-width requirements for
// elliptic curve coordinates.
//
// # Eligible Keys
//
// Keys that are not intended for signature verification are considered
// ineligible and will be skipped during parsing of a JWKS. A key is eligible
// if it meets at least one of the following criteria:
//
//   - The "use" (Public Key Use) parameter is set to "sig".
//   - The "key_ops" (Key Operations) parameter includes "verify".
//
// # Key Selection
//
// This implementation deliberately deviates from the RFC for robustness and
// simplicity:
//
//  1. The "alg" (Algorithm) parameter, optional in the standard, is treated as
//     mandatory for all eligible keys. Enforcing this is a best practice that
//     mitigates algorithm confusion attacks.
//  2. For key selection, the "kid" (Key ID) must be defined. Other lookup
//     mechanisms or thumbprint identifiers are not supported.
//
// # Usage
//
// Parse a JWKS from a remote endpoint and look up a key for verification.
//
// Example:
//
//	set, err := jwk.ParseSet(jsonData)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	key := set.Find(header)
package jwk
