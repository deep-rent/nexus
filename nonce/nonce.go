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
	"errors"
	"fmt"
)

const (
	// MinAlphabetSize is the minimum number of unique characters required in a
	// custom alphabet for [String].
	MinAlphabetSize = 2

	// MaxAlphabetSize is the maximum number of unique characters allowed in a
	// custom alphabet for [String].
	MaxAlphabetSize = 256
)

var (
	// ErrInvalidSize signals that a nonpositive size has been provided.
	ErrInvalidSize = errors.New("size must be positive")

	// ErrAlphabetTooSmall is returned when an alphabet contains fewer than
	// [MinAlphabetSize] characters.
	ErrAlphabetTooSmall = fmt.Errorf(
		"alphabet must contain at least %d characters",
		MinAlphabetSize,
	)

	// ErrAlphabetTooLarge is returned when an alphabet exceeds
	// [MaxAlphabetSize] characters.
	ErrAlphabetTooLarge = fmt.Errorf(
		"alphabet must contain at most %d characters",
		MaxAlphabetSize,
	)
)

// Bytes reads n cryptographically secure random bytes from [crypto/rand].
// It returns [ErrInvalidSize] if n is less than or equal to 0.
func Bytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, ErrInvalidSize
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
// Drawing 32 bytes of entropy produces a 43-character string. It returns
// [ErrInvalidSize] if n is less than or equal to 0.
func Opaque(n int) (string, error) {
	b, err := Bytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Hex draws n random bytes from [crypto/rand] and returns them encoded as a
// lowercase hexadecimal string.
//
// Drawing 32 bytes of entropy produces a 64-character hex string. It returns
// [ErrInvalidSize] if n is less than or equal to 0.
func Hex(n int) (string, error) {
	b, err := Bytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// String draws random bytes from [crypto/rand] and maps them uniformly onto
// the provided character alphabet using unbiased rejection sampling.
//
// It is UTF-8 safe and operates on Unicode runes, allowing custom alphabets to
// contain multi-byte characters. It is commonly used to generate
// human-readable PINs, user codes, or short verification tokens. It returns
// [ErrInvalidSize] if n is less than or equal to 0, [ErrAlphabetTooSmall] if
// the alphabet contains fewer than [MinAlphabetSize] characters, or
// [ErrAlphabetTooLarge] if the alphabet contains more than [MaxAlphabetSize]
// characters.
func String(n int, alphabet string) (string, error) {
	if n <= 0 {
		return "", ErrInvalidSize
	}
	runes := []rune(alphabet)
	N := len(runes)

	switch {
	case N < MinAlphabetSize:
		return "", ErrAlphabetTooSmall
	case N > MaxAlphabetSize:
		return "", ErrAlphabetTooLarge
	}

	// Calculate upper bound for unbiased rejection sampling.
	lim := MaxAlphabetSize - (MaxAlphabetSize % N)
	out := make([]rune, n)
	filled := 0

	b := make([]byte, n+(n/4)+4)

	for filled < n {
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		for _, w := range b {
			v := int(w)
			if v < lim {
				out[filled] = runes[v%N]
				filled++
				if filled == n {
					break
				}
			}
		}
	}
	return string(out), nil
}
