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

// Parser is a function that splits a SQL script into individual statements.
type Parser func(payload string) []string

// PostgresParser splits a PostgreSQL script into individual statements.
// It safely splits by semicolons while ignoring those within comments,
// string literals, identifiers, and PostgreSQL dollar quotes.
// It also allows splitting by a custom delimiter "-- nexus:split".
func PostgresParser(payload string) []string {
	const customDelimiter = "-- nexus:split"
	if strings.Contains(payload, customDelimiter) {
		var stmts []string
		for s := range strings.SplitSeq(payload, customDelimiter) {
			if trimmed := strings.TrimSpace(s); trimmed != "" {
				stmts = append(stmts, trimmed)
			}
		}
		return stmts
	}

	var stmts []string
	length := len(payload)
	start := 0

	inString := false
	inIdentifier := false
	inLineComment := false
	blockCommentDepth := 0
	var dollarQuote string

	// Iterate over bytes zero-alloc. Safe for UTF-8 since structural
	// characters are all ASCII and won't match multi-byte sequence parts.
	for i := 0; i < length; i++ {
		c := payload[i]

		// 1. Line Comments
		if inLineComment {
			if c == '\n' {
				inLineComment = false
			}
			continue
		}

		// 2. Block Comments (supports nesting)
		if blockCommentDepth > 0 {
			if c == '/' && i+1 < length && payload[i+1] == '*' {
				blockCommentDepth++
				i++
			} else if c == '*' && i+1 < length && payload[i+1] == '/' {
				blockCommentDepth--
				i++
			}
			continue
		}

		// 3. PostgreSQL Dollar Quotes
		if dollarQuote != "" {
			if c == '$' && strings.HasPrefix(payload[i:], dollarQuote) {
				i += len(dollarQuote) - 1
				dollarQuote = ""
			}
			continue
		}

		// 4. Single-quoted strings
		if inString {
			if c == '\'' {
				// Allow escaping by doubling the quote
				if i+1 < length && payload[i+1] == '\'' {
					i++
				} else {
					inString = false
				}
			}
			continue
		}

		// 5. Double-quoted identifiers
		if inIdentifier {
			if c == '"' {
				// Allow escaping by doubling the quote
				if i+1 < length && payload[i+1] == '"' {
					i++
				} else {
					inIdentifier = false
				}
			}
			continue
		}

		// 6. Lookahead for new state changes
		if c == '-' && i+1 < length && payload[i+1] == '-' {
			inLineComment = true
			i++
			continue
		}
		if c == '/' && i+1 < length && payload[i+1] == '*' {
			blockCommentDepth++
			i++
			continue
		}
		if c == '$' {
			endIdx := -1
			for j := i + 1; j < length; j++ {
				nc := payload[j]
				if nc == '$' {
					endIdx = j
					break
				}
				if !isDollarQuoteTagChar(nc) {
					break
				}
			}
			if endIdx != -1 {
				dollarQuote = payload[i : endIdx+1]
				i = endIdx
				continue
			}
		}
		if c == '\'' {
			inString = true
			continue
		}
		if c == '"' {
			inIdentifier = true
			continue
		}

		// 7. Statement boundary detection
		if c == ';' {
			if stmt := strings.TrimSpace(payload[start:i]); stmt != "" {
				stmts = append(stmts, stmt)
			}
			start = i + 1
			continue
		}
	}

	// Flush remaining buffer
	if start < length {
		if stmt := strings.TrimSpace(payload[start:]); stmt != "" {
			stmts = append(stmts, stmt)
		}
	}

	return stmts
}

// isDollarQuoteTagChar checks if a byte is a valid character for a PostgreSQL dollar quote tag.
func isDollarQuoteTagChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}
