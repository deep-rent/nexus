// Package snake provides functions for converting strings between camelCase
// and snake_case formats.
package snake

import (
	"strings"
	"unicode"
)

// ToUpper converts a camelCase string to an uppercase SNAKE_CASE string.
//
// For example, "fooBar" is converted to "FOO_BAR", and so is "FOOBar". Note
// that digits do not induce transitions, so "foo1" becomes "FOO1".
func ToUpper(s string) string { return transform(s, unicode.ToUpper) }

// ToLower converts a camelCase string to a lowercase snake_case string.
//
// For example, "fooBar" is converted to "foo_bar", and so is "FOOBar". Note
// that digits do not induce transitions, so "foo1" becomes "FOO1".
func ToLower(s string) string { return transform(s, unicode.ToLower) }

func transform(s string, toCase func(rune) rune) string {
	var b strings.Builder
	b.Grow(len(s) + 5)
	runes := []rune(s)
	for i, r := range runes {
		// Insert an underscore before a capital letter or digit.
		if i != 0 {
			q := runes[i-1]
			if (unicode.IsLower(q) &&
				// Case 1: Lowercase to uppercase/digit transition ("myVar", "myVar1").
				(unicode.IsUpper(r) || unicode.IsDigit(r))) ||
				(unicode.IsUpper(q) &&
					// Case 2: Acronym to new word transition ("MYVar").
					unicode.IsUpper(r) &&
					i+1 < len(runes) &&
					unicode.IsLower(runes[i+1])) {
				b.WriteRune('_')
			}
		}
		b.WriteRune(toCase(r))
	}
	return b.String()
}
