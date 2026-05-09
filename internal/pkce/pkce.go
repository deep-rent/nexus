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

// Package pkce provides utilities for generating and verifying
// Proof Key for Code Exchange (PKCE) parameters according to RFC 7636.
package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	// MethodS256 represents the SHA-256 challenge method.
	// This is the strongly recommended method by RFC 7636.
	MethodS256 = "S256"

	// MethodPlain represents the plain challenge method.
	// This should only be used if the client cannot support S256.
	MethodPlain = "plain"

	// MinVerifierLength is the minimum allowed length for a code verifier per
	// RFC 7636.
	MinVerifierLength = 43

	// MaxVerifierLength is the maximum allowed length for a code verifier per
	// RFC 7636.
	MaxVerifierLength = 128
)

var (
	// ErrInvalidLength indicates that the requested verifier length is outside
	// the RFC 7636 bounds.
	ErrInvalidLength = fmt.Errorf(
		"pkce: verifier length must be between %d and %d characters",
		MinVerifierLength,
		MaxVerifierLength,
	)

	// ErrUnsupportedMethod indicates that the provided challenge method is not
	// supported.
	ErrUnsupportedMethod = errors.New("pkce: unsupported challenge method")
)

// Supports checks if the provided challenge method is supported by this
// package.
func Supports(method string) bool {
	return method == MethodS256 || method == MethodPlain
}

// Verifier creates a cryptographically secure random string to serve as
// a PKCE code verifier. The length parameter determines the number of
// characters in the resulting string, which must be between [MinVerifierLength]
// and [MaxVerifierLength].
func Verifier(length int) (string, error) {
	if length < MinVerifierLength || length > MaxVerifierLength {
		return "", ErrInvalidLength
	}

	// Calculate the necessary number of random bytes.
	// Base64 encoding converts 3 bytes into 4 characters. Adding 1 ensures we
	// always generate slightly more than needed so we can safely truncate.
	byteLength := (length*3)/4 + 1
	b := make([]byte, byteLength)

	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	// Encode using RawURLEncoding to omit padding characters ('='),
	// making it URL-safe and fully compliant with RFC 7636.
	encoded := base64.RawURLEncoding.EncodeToString(b)

	// Truncate the encoded string to the exact requested length.
	return encoded[:length], nil
}

// Challenge computes a code challenge from a given code verifier and
// challenge method. For [MethodS256], it returns the Base64URL-encoded SHA256
// hash of the verifier. For [MethodPlain], it returns the verifier exactly as
// provided.
func Challenge(verifier, method string) (string, error) {
	if len(verifier) < MinVerifierLength || len(verifier) > MaxVerifierLength {
		return "", ErrInvalidLength
	}

	switch method {
	case MethodS256:
		// Hash the verifier using SHA-256 and encode the raw bytes.
		sum := sha256.Sum256([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(sum[:]), nil
	case MethodPlain:
		return verifier, nil
	default:
		return "", ErrUnsupportedMethod
	}
}

// Verify validates an incoming code verifier against the originally stored
// challenge. It returns true if the verifier securely matches the challenge
// based on the specified method.
func Verify(verifier, challenge, method string) bool {
	if len(challenge) == 0 || len(verifier) == 0 {
		return false
	}

	exp, err := Challenge(verifier, method)
	if err != nil {
		return false
	}

	// Ensure constant-time comparison doesn't panic due to unequal lengths.
	if len(exp) != len(challenge) {
		return false
	}

	// Mitigate timing attacks during verification.
	return subtle.ConstantTimeCompare([]byte(exp), []byte(challenge)) == 1
}
