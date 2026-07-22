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

package nonce

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
)

// Bytes reads n cryptographically secure random bytes from [crypto/rand].
// If n is less than or equal to 0, it returns a nil slice and no error.
func Bytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Opaque draws n random bytes from [crypto/rand] and returns them encoded as an
// unpadded base64url string.
//
// The output is safe for inclusion in URLs, HTTP headers, and JSON payloads.
// Drawing 32 bytes of entropy produces a 43-character string. If n is less
// than or equal to 0, it returns an empty string and no error.
func Opaque(n int) (string, error) {
	if n <= 0 {
		return "", nil
	}
	b, err := Bytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Hex draws n random bytes from [crypto/rand] and returns them encoded as a
// lowercase hexadecimal string.
//
// Drawing 32 bytes of entropy produces a 64-character hex string. If n is less
// than or equal to 0, it returns an empty string and no error.
func Hex(n int) (string, error) {
	if n <= 0 {
		return "", nil
	}
	b, err := Bytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// String draws n random bytes from [crypto/rand] and maps each byte uniformly
// onto the provided character alphabet.
//
// It is commonly used to generate human-readable PINs, user codes, or short
// verification tokens. If n is less than or equal to 0 or alphabet is empty, it
// returns an empty string and no error.
func String(n int, alphabet string) (string, error) {
	if n <= 0 || len(alphabet) == 0 {
		return "", nil
	}
	b, err := Bytes(n)
	if err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, val := range b {
		out[i] = alphabet[int(val)%len(alphabet)]
	}
	return string(out), nil
}
