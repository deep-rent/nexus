// Package quote provides simple, non-escaping utility functions for adding and
// removing a single layer of quotes from strings.
package quote

import (
	"fmt"
	"strings"
)

// Double surrounds a string with double quotes.
// This function does not handle escaping of quotes within the string.
func Double(s string) string {
	return fmt.Sprintf(`"%s"`, s)
}

// Single surrounds a string with single quotes.
// This function does not handle escaping of quotes within the string.
func Single(s string) string {
	return fmt.Sprintf("'%s'", s)
}

// Escape inserts backslashes before any occurrences of the quote character in
// the given string.
func Escape(s string, quote rune) string {
	return strings.ReplaceAll(s, string(quote), `\`+string(quote))
}

// Remove strips a single layer of surrounding single or double quotes from a
// string. If the string is not quoted or is too short, it is returned
// unchanged.
func Remove(s string) string {
	if len(s) < 2 {
		return s
	}
	// Check for a matching pair of quotes.
	switch s[0] {
	case '"':
		if s[len(s)-1] == '"' {
			return s[1 : len(s)-1]
		}
	case '\'':
		if s[len(s)-1] == '\'' {
			return s[1 : len(s)-1]
		}
	}
	// Return the original string if no matching quotes are found.
	return s
}
