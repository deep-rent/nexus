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

package schema

import "strings"

// Parse splits a SQL script into individual statements.
// It safely splits by semicolons while ignoring those within comments,
// string literals, identifiers, and PostgreSQL dollar quotes.
// It also allows splitting by a custom delimiter "-- nexus:split".
func Parse(payload string) []string {
	if strings.Contains(payload, "-- nexus:split") {
		var stmts []string
		for _, s := range strings.Split(payload, "-- nexus:split") {
			if trimmed := strings.TrimSpace(s); trimmed != "" {
				stmts = append(stmts, trimmed)
			}
		}
		return stmts
	}

	var stmts []string
	var buf strings.Builder

	runes := []rune(payload)
	length := len(runes)

	inString := false
	inIdentifier := false
	inLineComment := false
	blockCommentDepth := 0
	var dollarQuote string

	for i := 0; i < length; i++ {
		r := runes[i]

		// 1. Line Comments
		if inLineComment {
			buf.WriteRune(r)
			if r == '\n' {
				inLineComment = false
			}
			continue
		}

		// 2. Block Comments (supports nesting)
		if blockCommentDepth > 0 {
			buf.WriteRune(r)
			if r == '/' && i+1 < length && runes[i+1] == '*' {
				buf.WriteRune('*')
				i++
				blockCommentDepth++
			} else if r == '*' && i+1 < length && runes[i+1] == '/' {
				buf.WriteRune('/')
				i++
				blockCommentDepth--
			}
			continue
		}

		// 3. PostgreSQL Dollar Quotes
		if dollarQuote != "" {
			buf.WriteRune(r)
			if r == '$' {
				match := true
				tagRunes := []rune(dollarQuote)
				for j := 1; j < len(tagRunes); j++ {
					if i+j >= length || runes[i+j] != tagRunes[j] {
						match = false
						break
					}
				}
				if match {
					for j := 1; j < len(tagRunes); j++ {
						buf.WriteRune(runes[i+j])
					}
					i += len(tagRunes) - 1
					dollarQuote = ""
				}
			}
			continue
		}

		// 4. Single-quoted strings
		if inString {
			buf.WriteRune(r)
			if r == '\'' {
				// Allow escaping by doubling the quote
				if i+1 < length && runes[i+1] == '\'' {
					buf.WriteRune('\'')
					i++
				} else {
					inString = false
				}
			}
			continue
		}

		// 5. Double-quoted identifiers
		if inIdentifier {
			buf.WriteRune(r)
			if r == '"' {
				if i+1 < length && runes[i+1] == '"' {
					buf.WriteRune('"')
					i++
				} else {
					inIdentifier = false
				}
			}
			continue
		}

		// 6. Lookahead for new state changes
		if r == '-' && i+1 < length && runes[i+1] == '-' {
			inLineComment = true
			buf.WriteRune(r)
			buf.WriteRune('-')
			i++
			continue
		}
		if r == '/' && i+1 < length && runes[i+1] == '*' {
			blockCommentDepth++
			buf.WriteRune(r)
			buf.WriteRune('*')
			i++
			continue
		}
		if r == '$' {
			endIdx := -1
			for j := i + 1; j < length; j++ {
				if runes[j] == '$' {
					endIdx = j
					break
				}
				if !((runes[j] >= 'a' && runes[j] <= 'z') || (runes[j] >= 'A' && runes[j] <= 'Z') || (runes[j] >= '0' && runes[j] <= '9') || runes[j] == '_') {
					break
				}
			}
			if endIdx != -1 {
				dollarQuote = string(runes[i : endIdx+1])
				for j := i; j <= endIdx; j++ {
					buf.WriteRune(runes[j])
				}
				i = endIdx
				continue
			}
		}
		if r == '\'' {
			inString = true
			buf.WriteRune(r)
			continue
		}
		if r == '"' {
			inIdentifier = true
			buf.WriteRune(r)
			continue
		}

		// 7. Statement boundary detection
		if r == ';' {
			stmt := strings.TrimSpace(buf.String())
			if stmt != "" {
				stmts = append(stmts, stmt)
			}
			buf.Reset()
			continue
		}

		buf.WriteRune(r)
	}

	// Flush remaining buffer
	if stmt := strings.TrimSpace(buf.String()); stmt != "" {
		stmts = append(stmts, stmt)
	}

	return stmts
}
