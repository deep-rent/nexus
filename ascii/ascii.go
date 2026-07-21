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

// Package ascii provides fast, byte-based classification and conversion
// functions specifically for ASCII characters.
//
// It is designed as a lightweight alternative to the standard [unicode] package
// for cases where only basic ASCII support is required. By focusing strictly on
// the ASCII range, it avoids the overhead of large Unicode lookup tables,
// making it suitable for high-performance parsing and validation tasks.
//
// Operating on individual bytes rather than decoded runes is not a limitation
// for ASCII: every ASCII character encodes to a single byte, and in UTF-8 the
// bytes of a multi-byte rune are all greater than 0x7F, so they are simply
// reported as non-ASCII rather than being misclassified.
//
// # Usage
//
// You can use the classification functions to test bytes or conversion
// functions to shift casing.
//
// Example:
//
//	c := byte('A')
//	if ascii.IsUpper(c) {
//		lower := ascii.Lower(c) // 'a'
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

// IsUpper reports whether the byte is an uppercase ASCII letter
// ('A' through 'Z').
func IsUpper(c byte) bool { return lookup[c]&upp != 0 }

// IsLower reports whether the byte is a lowercase ASCII letter
// ('a' through 'z').
func IsLower(c byte) bool { return lookup[c]&low != 0 }

// IsDigit reports whether the byte is an ASCII decimal digit
// ('0' through '9').
func IsDigit(c byte) bool { return lookup[c]&dig != 0 }

// IsAlpha reports whether the byte is an ASCII letter (uppercase or lowercase).
func IsAlpha(c byte) bool { return lookup[c]&alphaMask != 0 }

// IsAlphaNum reports whether the byte is an ASCII letter or decimal digit.
func IsAlphaNum(c byte) bool { return lookup[c]&alphaNumMask != 0 }

// IsHex reports whether the given byte is a hexadecimal character
// ('0' through '9', 'a' through 'f', or 'A' through 'F').
func IsHex(c byte) bool { return lookup[c]&hexMask != 0 }

// IsWord reports whether the byte is an ASCII letter, digit, or underscore
// ('_').
//
// This is commonly used for validating variable names or identifiers.
func IsWord(c byte) bool { return IsAlphaNum(c) || c == '_' }

// IsSlug reports whether the byte is an ASCII letter, digit, or hyphen ('-').
//
// This is commonly used for validating URL path components.
func IsSlug(c byte) bool { return IsAlphaNum(c) || c == '-' }

// IsSpace reports whether the byte is a space character as defined
// by ASCII's property: ' ', '\t', '\n', '\v', '\f', '\r'.
func IsSpace(c byte) bool { return lookup[c]&isp != 0 }

// IsPrint reports whether the byte is a printable ASCII character,
// defined as any character from space (0x20) to tilde (0x7E).
func IsPrint(c byte) bool { return lookup[c]&printMask != 0 }

// IsControl reports whether the byte is an ASCII control character, defined as
// any character less than space (0x20) or the delete character (0x7F).
func IsControl(c byte) bool { return lookup[c]&ctl != 0 }

// IsPunct reports whether the byte is an ASCII punctuation character, one of
// !"#%&'()*,-./:;?@[\]_{}.
func IsPunct(c byte) bool { return lookup[c]&pun != 0 }

// IsSymbol reports whether the byte is an ASCII symbol character, one of
// $+<=>^`|~.
func IsSymbol(c byte) bool { return lookup[c]&sym != 0 }

// IsGraph reports whether the byte has a visible graphic representation,
// defined as any printable ASCII character except space
// ('!' (0x21) through '~' (0x7E)).
func IsGraph(c byte) bool { return lookup[c]&graphMask != 0 }

// IsASCII reports whether the byte is a valid ASCII character.
func IsASCII(c byte) bool { return c <= 0x7F }

// Lower converts an uppercase ASCII byte to lowercase.
//
// If the byte is not an uppercase letter, it is returned unchanged.
func Lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c | 0x20
	}
	return c
}

// Upper converts a lowercase ASCII byte to uppercase.
//
// If the byte is not a lowercase letter, it is returned unchanged.
func Upper(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c &^ 0x20
	}
	return c
}

// All reports whether every byte in the string satisfies the given predicate.
// If the string is empty, it returns true.
func All(s string, fn func(c byte) bool) bool {
	for i := 0; i < len(s); i++ {
		if !fn(s[i]) {
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

// Character class bits. Every printable code point belongs to exactly one of
// the exclusive classes below; the hex and whitespace bits are additive flags
// layered on top.
const (
	ctl uint16 = 1 << iota // control character
	spc                    // the space character (0x20)
	dig                    // decimal digit
	upp                    // uppercase letter
	low                    // lowercase letter
	pun                    // punctuation
	sym                    // symbol
	hex                    // hexadecimal digit (additive)
	isp                    // whitespace (additive; reported by IsSpace)
)

// Class masks combining the individual character class bits.
const (
	alphaMask    = upp | low                   // IsAlpha
	alphaNumMask = upp | low | dig             // IsAlphaNum
	hexMask      = dig | hex                   // IsHex
	graphMask    = upp | low | dig | pun | sym // IsGraph
	printMask    = graphMask | spc             // IsPrint
)

// Convenience combinations used when building the lookup table.
const (
	csp = ctl | isp // control character that is also whitespace
	tsp = spc | isp // the space character
	uhx = upp | hex // uppercase hexadecimal digit (A–F)
	lhx = low | hex // lowercase hexadecimal digit (a–f)
)

// lookup maps every byte to its set of character class bits. Entries for the
// non-ASCII bytes (0x80–0xFF) are zero, so those bytes belong to no class. The
// table is indexed by a byte, which is always in range, so the classification
// functions need neither a bounds check nor a preceding range test.
var lookup = [256]uint16{
	/* 00-07  NUL SOH STX ETX EOT ENQ ACK BEL */
	ctl, ctl, ctl, ctl, ctl, ctl, ctl, ctl,
	/* 08-0F  BS  HT  LF  VT  FF  CR  SO  SI  */
	ctl, csp, csp, csp, csp, csp, ctl, ctl,
	/* 10-17  DLE DC1 DC2 DC3 DC4 NAK SYN ETB */
	ctl, ctl, ctl, ctl, ctl, ctl, ctl, ctl,
	/* 18-1F  CAN EM  SUB ESC FS  GS  RS  US  */
	ctl, ctl, ctl, ctl, ctl, ctl, ctl, ctl,
	/* 20-27  SP  !   "   #   $   %   &   '   */
	tsp, pun, pun, pun, sym, pun, pun, pun,
	/* 28-2F  (   )   *   +   ,   -   .   /   */
	pun, pun, pun, sym, pun, pun, pun, pun,
	/* 30-37  0   1   2   3   4   5   6   7   */
	dig, dig, dig, dig, dig, dig, dig, dig,
	/* 38-3F  8   9   :   ;   <   =   >   ?   */
	dig, dig, pun, pun, sym, sym, sym, pun,
	/* 40-47  @   A   B   C   D   E   F   G   */
	pun, uhx, uhx, uhx, uhx, uhx, uhx, upp,
	/* 48-4F  H   I   J   K   L   M   N   O   */
	upp, upp, upp, upp, upp, upp, upp, upp,
	/* 50-57  P   Q   R   S   T   U   V   W   */
	upp, upp, upp, upp, upp, upp, upp, upp,
	/* 58-5F  X   Y   Z   [   \   ]   ^   _   */
	upp, upp, upp, pun, pun, pun, sym, pun,
	/* 60-67  `   a   b   c   d   e   f   g   */
	sym, lhx, lhx, lhx, lhx, lhx, lhx, low,
	/* 68-6F  h   i   j   k   l   m   n   o   */
	low, low, low, low, low, low, low, low,
	/* 70-77  p   q   r   s   t   u   v   w   */
	low, low, low, low, low, low, low, low,
	/* 78-7F  x   y   z   {   |   }   ~   DEL */
	low, low, low, pun, sym, pun, sym, ctl,
	// 0x80–0xFF are non-ASCII; every entry is zero (no class).
}
