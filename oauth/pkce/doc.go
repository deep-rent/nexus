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

// Package pkce provides utilities for generating and verifying Proof Key for
// Code Exchange (PKCE) parameters according to RFC 7636.
//
// The package implements the core logic required for OAuth 2.0 public clients
// to prevent authorization code injection attacks. It handles the creation of
// high-entropy verifiers and the derivation of challenges using both SHA-256
// and plain transformations.
//
// # Usage
//
// To perform a PKCE exchange, first generate a verifier and its corresponding
// challenge to include in the authorization request. Later, use the verifier
// in the token exchange and validate it using the [Verify] function.
//
// Basic Example:
//
//	// Generate a 128-character verifier.
//	verifier, _ := pkce.Verifier(128)
//
//	// Create a challenge using the S256 method.
//	challenge, _ := pkce.Challenge(verifier, pkce.MethodS256)
//
//	// On the server side, verify the incoming verifier against the challenge.
//	valid := pkce.Verify(verifier, challenge, pkce.MethodS256)
package pkce
