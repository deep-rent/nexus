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

import (
	"strings"

	"github.com/deep-rent/nexus/internal/ascii"
)

// Parser is a function that splits a SQL script into individual statements.
type Parser func(payload string) []string

// Postgres splits a PostgreSQL script into individual statements.
// It safely splits by semicolons while ignoring those within comments,
// string literals, identifiers, and PostgreSQL dollar quotes.
// It also allows splitting by a custom delimiter "-- nexus:split".
func Postgres(payload string) []string {
	const delim = "-- nexus:split"
	if strings.Contains(payload, delim) {
		var stmts []string
		for s := range strings.SplitSeq(payload, delim) {
			if trimmed := strings.TrimSpace(s); trimmed != "" {
				stmts = append(stmts, trimmed)
			}
		}
		return stmts
	}

	var stmts []string
	length := len(payload)
	start := 0

	inQuotes := false
	inId := false
	inLineComment := false
	blockCommentDepth := 0
	var dq string

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
		if dq != "" {
			if c == '$' && strings.HasPrefix(payload[i:], dq) {
				i += len(dq) - 1
				dq = ""
			}
			continue
		}

		// 4. Single-quoted strings
		if inQuotes {
			if c == '\'' {
				// Allow escaping by doubling the quote
				if i+1 < length && payload[i+1] == '\'' {
					i++
				} else {
					inQuotes = false
				}
			}
			continue
		}

		// 5. Double-quoted identifiers
		if inId {
			if c == '"' {
				// Allow escaping by doubling the quote
				if i+1 < length && payload[i+1] == '"' {
					i++
				} else {
					inId = false
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
				if !ascii.IsWord(rune(nc)) {
					break
				}
			}
			if endIdx != -1 {
				dq = payload[i : endIdx+1]
				i = endIdx
				continue
			}
		}
		if c == '\'' {
			inQuotes = true
			continue
		}
		if c == '"' {
			inId = true
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
