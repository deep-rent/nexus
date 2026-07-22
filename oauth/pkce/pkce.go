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

package pkce

import (
	"context"
	"errors"
	"fmt"

	"github.com/deep-rent/nexus/ascii"
	"github.com/deep-rent/nexus/digest"
	"github.com/deep-rent/nexus/nonce"
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
	// the RFC 7636 bounds defined by [MinVerifierLength] and
	// [MaxVerifierLength].
	ErrInvalidLength = fmt.Errorf(
		"verifier length must be between %d and %d characters",
		MinVerifierLength,
		MaxVerifierLength,
	)

	// ErrUnsupportedMethod indicates that the provided challenge method is not
	// supported. Valid methods are [MethodS256] and [MethodPlain].
	ErrUnsupportedMethod = errors.New("unsupported challenge method")

	// ErrInvalidVerifier indicates that the provided code verifier contains
	// characters that are not allowed by RFC 7636.
	ErrInvalidVerifier = errors.New("code verifier contains invalid characters")
)

// Supports checks if the provided challenge method string is supported by this
// package. It returns true for [MethodS256] and [MethodPlain].
func Supports(method string) bool {
	return method == MethodS256 || method == MethodPlain
}

// Verifier creates a cryptographically secure random string to serve as a PKCE
// code verifier. The length parameter determines the number of characters in
// the resulting string, which must be between [MinVerifierLength] and
// [MaxVerifierLength].
//
// Characters are sampled uniformly from [Alphabet] via a [nonce.Sampler].
func Verifier(length int) (string, error) {
	if length < MinVerifierLength || length > MaxVerifierLength {
		return "", ErrInvalidLength
	}
	return nonce.NewSampler(nil, Alphabet, length).Draw(context.Background())
}

// Challenge computes a code challenge from a given code verifier and challenge
// method. For [MethodS256], it returns the Base64URL-encoded SHA-256 hash of
// the verifier (its [digest.DefaultHasher] fingerprint). For [MethodPlain], it
// returns the verifier exactly as provided. It returns [ErrInvalidLength] if
// the verifier length is non-compliant.
func Challenge(verifier, method string) (string, error) {
	if len(verifier) < MinVerifierLength || len(verifier) > MaxVerifierLength {
		return "", ErrInvalidLength
	}

	if !IsUnreserved(verifier) {
		return "", ErrInvalidVerifier
	}

	switch method {
	case MethodS256:
		return digest.DefaultHasher.String(verifier), nil
	case MethodPlain:
		return verifier, nil
	default:
		return "", ErrUnsupportedMethod
	}
}

// Verify validates an incoming code verifier against the originally stored
// challenge. It returns true if the verifier matches the challenge for the
// specified method, comparing in constant time via [digest] to mitigate timing
// attacks.
func Verify(verifier, challenge, method string) bool {
	if len(challenge) == 0 || len(verifier) == 0 {
		return false
	}

	if len(verifier) < MinVerifierLength || len(verifier) > MaxVerifierLength {
		return false
	}

	if !IsUnreserved(verifier) {
		return false
	}

	switch method {
	case MethodS256:
		// Match fingerprints the verifier and compares it to the stored
		// challenge in constant time; a length mismatch is a non-match.
		return digest.DefaultHasher.Match(verifier, challenge)

	case MethodPlain:
		if len(challenge) < MinVerifierLength ||
			len(challenge) > MaxVerifierLength {
			return false
		}
		// Fingerprint both values so the constant-time compare sees
		// equal-length inputs, mitigating length-based timing leaks.
		return digest.Equal(
			digest.DefaultHasher.String(verifier),
			digest.DefaultHasher.String(challenge),
		)

	default:
		return false
	}
}

// Alphabet is the set of unreserved characters allowed in a PKCE code verifier,
// as defined in RFC 7636 Section 4.1.
const Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

// isUnreserved reports whether the given string contains only unreserved ASCII
// characters.
//
// According to RFC 7636 Section 4.1, unreserved characters are:
// [A-Z], [a-z], [0-9], "-", ".", "_", "~".
func IsUnreserved(s string) bool { return ascii.All(s, isUnreserved) }

func isUnreserved(c byte) bool {
	return ascii.IsAlphaNum(c) || c == '-' || c == '.' || c == '_' || c == '~'
}
