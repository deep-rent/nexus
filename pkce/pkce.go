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

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	// MethodS256 represents the SHA-256 challenge method. This is the strongly
	// recommended method by RFC 7636 as it prevents the verifier from being
	// intercepted in the authorization request.
	MethodS256 = "S256"
	// MethodPlain represents the plain challenge method. This should only be
	// used if the client is highly constrained and cannot support [MethodS256],
	// as it provides less security against interception.
	MethodPlain = "plain"
)

const (
	// MinVerifierLength is the minimum allowed length for a code verifier per
	// RFC 7636 (43 characters).
	MinVerifierLength = 43
	// MaxVerifierLength is the maximum allowed length for a code verifier per
	// RFC 7636 (128 characters).
	MaxVerifierLength = 128
)

var (
	// ErrInvalidLength indicates that the requested verifier length is outside
	// the RFC 7636 bounds defined by [MinVerifierLength] and [MaxVerifierLength].
	ErrInvalidLength = fmt.Errorf(
		"pkce: verifier length must be between %d and %d characters",
		MinVerifierLength,
		MaxVerifierLength,
	)

	// ErrUnsupportedMethod indicates that the provided challenge method is not
	// supported. Valid methods are [MethodS256] and [MethodPlain].
	ErrUnsupportedMethod = errors.New("pkce: unsupported challenge method")

	// ErrInvalidVerifier indicates that the provided code verifier contains
	// characters that are not allowed by RFC 7636.
	ErrInvalidVerifier = errors.New("pkce: code verifier contains invalid characters")
)

// Supports checks if the provided challenge method string is supported by this
// package. It returns true for [MethodS256] and [MethodPlain].
func Supports(method string) bool {
	return method == MethodS256 || method == MethodPlain
}

// isValidVerifier checks if a string only contains unreserved characters
// as defined in RFC 7636 Section 4.1: [A-Z], [a-z], [0-9], "-", ".", "_", "~".
func isValidVerifier(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			continue
		}
		return false
	}
	return true
}

// Verifier creates a cryptographically secure random string to serve as a PKCE
// code verifier. The length parameter determines the number of characters in
// the resulting string, which must be between [MinVerifierLength] and
// [MaxVerifierLength].
func Verifier(length int) (string, error) {
	if length < MinVerifierLength || length > MaxVerifierLength {
		return "", ErrInvalidLength
	}

	// Calculate the necessary number of random bytes. Base64 encoding converts
	// 3 bytes into 4 characters. Adding 1 ensures we always generate slightly
	// more than needed so we can safely truncate to the exact requested length.
	b := make([]byte, (length*3)/4+1)

	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	// Encode using RawURLEncoding to omit padding characters ('='), making it
	// URL-safe and fully compliant with the ABNF definition in RFC 7636.
	encoded := base64.RawURLEncoding.EncodeToString(b)

	// Truncate the encoded string to the exact requested length.
	return encoded[:length], nil
}

// Challenge computes a code challenge from a given code verifier and challenge
// method. For [MethodS256], it returns the Base64URL-encoded SHA256 hash of the
// verifier. For [MethodPlain], it returns the verifier exactly as provided.
// It returns [ErrInvalidLength] if the verifier length is non-compliant.
func Challenge(verifier, method string) (string, error) {
	if len(verifier) < MinVerifierLength || len(verifier) > MaxVerifierLength {
		return "", ErrInvalidLength
	}

	if !isValidVerifier(verifier) {
		return "", ErrInvalidVerifier
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
// based on the specified method. This function uses constant-time comparison
// via [subtle.ConstantTimeCompare] to mitigate timing attacks.
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

	// Mitigate timing attacks during verification by ensuring the comparison
	// time does not depend on the contents of the strings.
	return subtle.ConstantTimeCompare([]byte(exp), []byte(challenge)) == 1
}
