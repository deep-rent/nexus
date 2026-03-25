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

// Package quote provides utility functions for working with quoted strings.
package quote

// Remove strips a single layer of surrounding single or double quotes from a
// string. If the string is not quoted or too short, it is returned unchanged.
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

// RemoveAll strips all layers of surrounding quotes from a string,
// regardless of quote type mixing (e.g., "'hello'" becomes hello).
func RemoveAll(s string) string {
	for {
		unquoted := Remove(s)
		if unquoted == s {
			break
		}
		s = unquoted
	}
	return s
}

// Has returns true if the string is surrounded by a matching pair
// of single or double quotes.
func Has(s string) bool {
	if len(s) < 2 {
		return false
	}
	switch s[0] {
	case '"', '\'':
		return s[len(s)-1] == s[0]
	}
	return false
}

// Wrap surrounds the given string with the specified quote character.
// Note: It does not escape existing quotes inside the string.
func Wrap(s string, q rune) string {
	r := string(q)
	return r + s + r
}

// Double wraps a string in double quotes.
func Double(s string) string { return Wrap(s, '"') }

// Single wraps a string in single quotes.
func Single(s string) string { return Wrap(s, '\'') }

// Is checks if the given rune is a single or double quote character.
func Is(c rune) bool { return c == '"' || c == '\'' }
