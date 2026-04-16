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

// Package ascii provides fast, rune-based classification and conversion
// functions specifically for ASCII characters.
//
// It is designed as a lightweight alternative to the standard [unicode] package
// for cases where only basic ASCII support is required. By focusing strictly on
// the ASCII range, it avoids the overhead of large Unicode lookup tables,
// making it suitable for high-performance parsing and validation tasks.
//
// # Usage
//
// You can use the classification functions to validate runes or conversion
// functions to shift casing.
//
// Example:
//
//	r := 'A'
//	if ascii.IsUpper(r) {
//		lower := ascii.ToLower(r) // 'a'
//	}
package ascii

// IsUpper reports whether the rune is an uppercase ASCII letter
// ('A' through 'Z').
func IsUpper(c rune) bool { return c >= 'A' && c <= 'Z' }

// IsLower reports whether the rune is a lowercase ASCII letter
// ('a' through 'z').
func IsLower(c rune) bool { return c >= 'a' && c <= 'z' }

// IsDigit reports whether the rune is an ASCII decimal digit
// ('0' through '9').
func IsDigit(c rune) bool { return c >= '0' && c <= '9' }

// IsAlpha reports whether the rune is an ASCII letter (uppercase or lowercase).
func IsAlpha(c rune) bool { return IsUpper(c) || IsLower(c) }

// IsAlphaNum reports whether the rune is an ASCII letter or decimal digit.
func IsAlphaNum(c rune) bool { return IsAlpha(c) || IsDigit(c) }

// IsWord reports whether the rune is an ASCII letter, digit, or underscore
// ('_').
//
// This is commonly used for validating variable names or identifiers.
func IsWord(c rune) bool { return IsAlphaNum(c) || c == '_' }

// IsSlug reports whether the rune is an ASCII letter, digit, or hyphen ('-').
//
// This is commonly used for validating URL path components.
func IsSlug(c rune) bool { return IsAlphaNum(c) || c == '-' }

// ToLower converts an uppercase ASCII rune to lowercase.
//
// If the rune is not an uppercase letter, it is returned unchanged.
func ToLower(c rune) rune {
	if IsUpper(c) {
		return c + ('a' - 'A')
	}
	return c
}

// ToUpper converts a lowercase ASCII rune to uppercase.
//
// If the rune is not a lowercase letter, it is returned unchanged.
func ToUpper(c rune) rune {
	if IsLower(c) {
		return c - ('a' - 'A')
	}
	return c
}
