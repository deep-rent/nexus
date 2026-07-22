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

// Package nonce offers high-entropy random token, handle, and string
// generation utilities backed by the system's cryptographically secure random
// number generator.
//
// # Usage
//
// Generate an opaque bearer token and a hex handle:
//
//	tok, err := nonce.Opaque(32) // 32 bytes of entropy (43 base64url chars)
//	hex, err := nonce.Hex(32)    // 32 bytes of entropy (64 hex chars)
//
// Generate a 6-digit numeric verification PIN:
//
//	pin, err := nonce.String(6, "0123456789")
package nonce
