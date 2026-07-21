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
//		lower := ascii.Lower(r) // 'a'
//	}
package ascii

// Named code points for the ASCII characters that lack a printable symbol,
// covering the C0 control set (0x00–0x1F), the space character (0x20), and
// the delete character (0x7F).
//
// The constants are untyped, so they can be used interchangeably as a [rune]
// or a [byte].
const (
	NUL = 0x00 // '\0' Null
	SOH = 0x01 //      Start of Heading
	STX = 0x02 //      Start of Text
	ETX = 0x03 //      End of Text
	EOT = 0x04 //      End of Transmission
	ENQ = 0x05 //      Enquiry
	ACK = 0x06 //      Acknowledgement
	BEL = 0x07 // '\a' Bell
	BS  = 0x08 // '\b' Backspace
	HT  = 0x09 // '\t' Horizontal Tab
	LF  = 0x0A // '\n' Line Feed
	VT  = 0x0B // '\v' Vertical Tab
	FF  = 0x0C // '\f' Form Feed
	CR  = 0x0D // '\r' Carriage Return
	SO  = 0x0E //      Shift Out
	SI  = 0x0F //      Shift In
	DLE = 0x10 //      Data Link Escape
	DC1 = 0x11 //      Device Control 1
	DC2 = 0x12 //      Device Control 2
	DC3 = 0x13 //      Device Control 3
	DC4 = 0x14 //      Device Control 4
	NAK = 0x15 //      Negative Acknowledgement
	SYN = 0x16 //      Synchronous Idle
	ETB = 0x17 //      End of Transmission Block
	CAN = 0x18 //      Cancel
	EM  = 0x19 //      End of Medium
	SUB = 0x1A //      Substitute
	ESC = 0x1B // '\e' Escape
	FS  = 0x1C //      File Separator
	GS  = 0x1D //      Group Separator
	RS  = 0x1E //      Record Separator
	US  = 0x1F //      Unit Separator
	SP  = 0x20 //      Space
	DEL = 0x7F //      Delete
)

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

// IsHex reports whether the given rune is a hexadecimal character.
func IsHex(c rune) bool {
	return IsDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// IsWord reports whether the rune is an ASCII letter, digit, or underscore
// ('_').
//
// This is commonly used for validating variable names or identifiers.
func IsWord(c rune) bool { return IsAlphaNum(c) || c == '_' }

// IsSlug reports whether the rune is an ASCII letter, digit, or hyphen ('-').
//
// This is commonly used for validating URL path components.
func IsSlug(c rune) bool { return IsAlphaNum(c) || c == '-' }

// IsSpace reports whether the rune is a space character as defined
// by ASCII's property: ' ', '\t', '\n', '\v', '\f', '\r'.
func IsSpace(c rune) bool {
	switch c {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	}
	return false
}

// IsPrint reports whether the rune is a printable ASCII character,
// defined as any character from space (0x20) to tilde (0x7E).
func IsPrint(c rune) bool { return c >= 0x20 && c <= 0x7E }

// IsControl reports whether the rune is an ASCII control character, defined as
// any character less than space (0x20) or the delete character (0x7F).
func IsControl(c rune) bool { return c < 0x20 || c == 0x7F }

// IsASCII reports whether the rune is a valid ASCII character.
func IsASCII(c rune) bool { return c <= 0x7F }

// Lower converts an uppercase ASCII rune to lowercase.
//
// If the rune is not an uppercase letter, it is returned unchanged.
func Lower(c rune) rune {
	if c >= 'A' && c <= 'Z' {
		return c | 0x20
	}
	return c
}

// Upper converts a lowercase ASCII rune to uppercase.
//
// If the rune is not a lowercase letter, it is returned unchanged.
func Upper(c rune) rune {
	if c >= 'a' && c <= 'z' {
		return c &^ 0x20
	}
	return c
}

// All reports whether every byte in the string, interpreted as a rune,
// satisfies the given predicate. If the string is empty, it returns true.
func All(s string, fn func(c rune) bool) bool {
	for i := 0; i < len(s); i++ {
		if !fn(rune(s[i])) {
			return false
		}
	}
	return true
}

// EqualFold is a fast, ASCII-only case-insensitive string comparison.
// It avoids the overhead of unicode-aware casing rules found in
// [strings.EqualFold].
func EqualFold(s, t string) bool {
	if len(s) != len(t) {
		return false
	}
	for i := 0; i < len(s); i++ {
		a, b := s[i], t[i]
		if a == b {
			continue
		}
		// Convert both to lowercase using bitwise OR and compare.
		if a >= 'A' && a <= 'Z' {
			a |= 0x20
		}
		if b >= 'A' && b <= 'Z' {
			b |= 0x20
		}
		if a != b {
			return false
		}
	}
	return true
}

// HasUpper reports whether the string contains any uppercase ASCII letters.
func HasUpper(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			return true
		}
	}
	return false
}

// HasLower reports whether the string contains any lowercase ASCII letters.
func HasLower(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'a' && s[i] <= 'z' {
			return true
		}
	}
	return false
}

// ToLower returns a copy of the string with all ASCII letters mapped to their
// lower case.
func ToLower(s string) string {
	if !HasUpper(s) {
		return s
	}
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c |= 0x20
		}
		b[i] = c
	}
	return string(b)
}

// ToUpper returns a copy of the string with all ASCII letters mapped to their
// upper case.
func ToUpper(s string) string {
	if !HasLower(s) {
		return s
	}
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c &^= 0x20
		}
		b[i] = c
	}
	return string(b)
}
