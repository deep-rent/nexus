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
type Parser func(script string) []string

// Postgres splits a PostgreSQL script into individual statements.
// It safely splits by semicolons while ignoring those within comments,
// string literals, identifiers, and PostgreSQL dollar quotes.
// It also allows splitting by a custom delimiter "-- nexus:split".
func Postgres(script string) []string {
	const delim = "-- nexus:split"
	if strings.Contains(script, delim) {
		var stmts []string
		for s := range strings.SplitSeq(script, delim) {
			if t := strings.TrimSpace(s); t != "" {
				stmts = append(stmts, t)
			}
		}
		return stmts
	}

	var stmts []string
	n := len(script)
	start := 0

	inQuotes := false
	inId := false
	inComment := false
	blockCommentDepth := 0
	var q string

	// Iterate over bytes zero-alloc. Safe for UTF-8 since structural
	// characters are all ASCII and won't match multi-byte sequence parts.
	for i := 0; i < n; i++ {
		c := script[i]

		// 1. Line Comments
		if inComment {
			if c == '\n' {
				inComment = false
			}
			continue
		}

		// 2. Block Comments (supports nesting)
		if blockCommentDepth > 0 {
			if c == '/' && i+1 < n && script[i+1] == '*' {
				blockCommentDepth++
				i++
			} else if c == '*' && i+1 < n && script[i+1] == '/' {
				blockCommentDepth--
				i++
			}
			continue
		}

		// 3. PostgreSQL Dollar Quotes
		if q != "" {
			if c == '$' && strings.HasPrefix(script[i:], q) {
				i += len(q) - 1
				q = ""
			}
			continue
		}

		// 4. Single-quoted strings
		if inQuotes {
			if c == '\'' {
				// Allow escaping by doubling the quote
				if i+1 < n && script[i+1] == '\'' {
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
				if i+1 < n && script[i+1] == '"' {
					i++
				} else {
					inId = false
				}
			}
			continue
		}

		// 6. Lookahead for new state changes
		if c == '-' && i+1 < n && script[i+1] == '-' {
			inComment = true
			i++
			continue
		}
		if c == '/' && i+1 < n && script[i+1] == '*' {
			blockCommentDepth++
			i++
			continue
		}
		if c == '$' {
			end := -1
			for j := i + 1; j < n; j++ {
				nc := script[j]
				if nc == '$' {
					end = j
					break
				}
				if !ascii.IsWord(rune(nc)) {
					break
				}
			}
			if end != -1 {
				q = script[i : end+1]
				i = end
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
			if stmt := strings.TrimSpace(script[start:i]); stmt != "" {
				stmts = append(stmts, stmt)
			}
			start = i + 1
			continue
		}
	}

	// Flush the remaining buffer
	if start < n {
		if stmt := strings.TrimSpace(script[start:]); stmt != "" {
			stmts = append(stmts, stmt)
		}
	}

	return stmts
}
