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

package header

import (
	"iter"
	"strings"
)

// fields splits a header value on sep, skipping separators that appear inside
// a quoted string or between angle brackets.
//
// A plain [strings.Split] is not sufficient for header values: RFC 9110 allows
// list members to carry quoted strings, and RFC 8288 wraps link targets in
// angle brackets. Both may legitimately contain the separator, as in
// `no-cache="Set-Cookie", max-age=60` or a link whose query string enumerates
// several identifiers.
//
// Fields are yielded verbatim, including any surrounding whitespace and
// quotes.
func fields(s string, sep byte) iter.Seq[string] {
	return func(yield func(string) bool) {
		var (
			start  int  // index at which the current field begins
			quoted bool // inside a quoted string
			escape bool // previous byte was a backslash within quotes
			angle  bool // inside angle brackets
		)

		for i := range len(s) {
			switch c := s[i]; {
			case escape:
				// Any byte following a backslash is literal.
				escape = false
			case quoted && c == '\\':
				escape = true
			case c == '"':
				quoted = !quoted
			case quoted:
				// Separators inside a quoted string belong to the value.
			case c == '<':
				angle = true
			case c == '>':
				angle = false
			case c == sep && !angle:
				if !yield(s[start:i]) {
					return
				}
				start = i + 1
			}
		}

		// The remainder after the last separator forms the final field. An
		// empty input yields a single empty field, matching strings.Split.
		yield(s[start:])
	}
}

// unquote removes the surrounding double quotes from a header parameter value
// and resolves any backslash escapes within them. Values that are not quoted
// are returned unchanged.
func unquote(s string) string {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return s
	}

	s = s[1 : len(s)-1]
	if !strings.ContainsRune(s, '\\') {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
