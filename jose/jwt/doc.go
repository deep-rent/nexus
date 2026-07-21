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

// Package jwt provides tools for parsing, verifying, and signing JSON Web
// Tokens (JWTs).
//
// This package uses generics to allow users to define their own custom claims
// structures. A common pattern is to embed the provided [Reserved] claims
// struct and add extra fields for any other claims present in the token.
//
// # Basic Verification
//
// Start by defining custom claims:
//
//	type Claims struct {
//	  jwt.Reserved
//	  Scope string         `json:"scp"`
//	  Extra map[string]any `json:",embed"`
//	}
//
// The top-level [Verify] function can be used for simple, one-off signature
// verification without claim validation:
//
//	set, err := jwk.ParseSet(`{"keys": [...]}`)
//	if err != nil { /* handle parsing error */ }
//	claims, err := jwt.Verify[Claims](set, []byte("eyJhb..."))
//
// # Advanced Validation
//
// For advanced validation of claims like issuer, audience, and token age,
// create a reusable [Verifier] with the desired configuration using functional
// options:
//
//	verifier := jwt.NewVerifier[Claims](
//	  set,
//	  jwt.WithIssuers("foo", "bar"),
//	  jwt.WithAudiences("baz"),
//	  jwt.WithLeeway(1 * time.Minute),
//	  jwt.WithMaxAge(1 * time.Hour),
//	)
//
//	claims, err := verifier.Verify([]byte("eyJhb..."))
//	if err != nil { /* handle validation error */ }
//	fmt.Println("Scope:", claims.Scope)
//
// # Signing
//
// The top-level [Sign] function can be used to create signed tokens from any
// JSON-serializable struct or map. It requires a [jwk.KeyPair] for signature
// calculation.
//
//	claims := &MyClaims{
//	  Reserved: jwt.Reserved{
//	    Sub: "user_123",
//	    Exp: time.Now().Add(time.Hour),
//	  },
//	  Scope: "admin",
//	}
//	token, err := jwt.Sign(key, claims)
package jwt
