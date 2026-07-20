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
//
// It offers a suite of tools for detecting, applying, and stripping single or
// double quotes from string data. These utilities are particularly helpful
// when parsing configuration files, processing CLI arguments, or normalizing
// user input where string literals may be wrapped in various quote styles.
//
// # Usage
//
// The package supports both single-layer operations and recursive unquoting.
//
// Example:
//
//	// Remove a single layer
//	s := quote.Remove(`"hello"`) // returns: hello
//
//	// Remove nested layers
//	s = quote.RemoveAll(`"'nested'"`) // returns: nested
//
//	// Wrap content
//	s = quote.Double("content") // returns: "content"
//
// It also provides SQL quoting helpers that escape embedded quotes:
//
//	// Quote SQL identifiers and literals
//	s = quote.Ident("public", "users") // returns: "public"."users"
//	s = quote.Literal("it's")          // returns: 'it''s'
package quote

import "strings"

// Remove strips a single layer of surrounding single or double quotes from a
// string.
//
// If the string is not quoted or is too short to contain a matching pair, it is
// returned unchanged.
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

// RemoveAll strips all layers of surrounding quotes from a string, regardless
// of quote type mixing (e.g., "'hello'" becomes hello).
//
// It repeatedly applies [Remove] until no further changes are detected in the
// input string.
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

// Has returns true if the string is surrounded by a matching pair of single or
// double quotes.
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
//
// Note: It does not escape existing quotes inside the string. It essentially
// performs a simple concatenation of the quote rune and the content.
func Wrap(s string, q rune) string {
	r := string(q)
	return r + s + r
}

// Double wraps a string in double quotes using [Wrap].
func Double(s string) string { return Wrap(s, '"') }

// Single wraps a string in single quotes using [Wrap].
func Single(s string) string { return Wrap(s, '\'') }

// Is checks if the given rune is a single or double quote character.
func Is(c rune) bool { return c == '"' || c == '\'' }

// Escape safely quotes a SQL identifier: embedded double quotes are doubled
// and the result is wrapped in double quotes using [Double].
func Escape(s string) string {
	return Double(strings.ReplaceAll(s, `"`, `""`))
}

// Ident assembles a fully qualified SQL identifier by escaping each part
// with [Escape] and joining the parts with dots (e.g., "schema"."table").
// It panics if no parts are given (programmer error).
func Ident(parts ...string) string {
	if len(parts) == 0 {
		panic("at least one part is required")
	}
	escaped := make([]string, len(parts))
	for i, part := range parts {
		escaped[i] = Escape(part)
	}
	return strings.Join(escaped, ".")
}

// Literal safely quotes a SQL string literal: embedded single quotes are
// doubled and the result is wrapped in single quotes using [Single].
func Literal(s string) string {
	return Single(strings.ReplaceAll(s, "'", "''"))
}
