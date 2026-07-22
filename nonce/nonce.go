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

const defaultBytes = 32

// Bytes generates n cryptographically secure random bytes from crypto/rand.
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

// Opaque generates a high-entropy, base64url-encoded string suitable for use as
// a secure token. Drawing 32 bytes (default) yields a 43-character string.
func Opaque(bytesLen ...int) (string, error) {
	n := defaultBytes
	if len(bytesLen) > 0 && bytesLen[0] > 0 {
		n = bytesLen[0]
	}
	b, err := Bytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Hex generates a high-entropy, hex-encoded random string. Drawing 32 bytes
// (default) yields a 64-character hex string.
func Hex(bytesLen ...int) (string, error) {
	n := defaultBytes
	if len(bytesLen) > 0 && bytesLen[0] > 0 {
		n = bytesLen[0]
	}
	b, err := Bytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// String generates a random string of length n drawn uniformly from an
// alphabet.
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
