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

// Package opaque provides utilities for generating cryptographically secure,
// opaque strings intended for use as tokens, identifiers, or secrets.
//
// The package ensures that generated strings utilize a high-entropy source
// and are encoded in a URL-safe format, making them suitable for transport
// in HTTP headers, query parameters, or cookies.
//
// # Usage
//
// Generate a new secure token for session management or API authentication.
//
// Example:
//
//	// Create a secure 32-byte (encoded) random string.
//	token, err := opaque.Generate()
//	if err != nil {
//		// Handle cryptographic source error.
//	}
//	fmt.Println("Generated token:", token)
package opaque

import (
	"crypto/rand"
	"encoding/base64"
)

// Generate creates a cryptographically secure random string by reading 32
// bytes from [rand.Reader] and encoding them using [base64.RawURLEncoding].
// This produces a high-entropy string that is safe for use in URLs and
// persistent storage.
func Generate() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
