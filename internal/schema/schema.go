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

// Package schema provides utilities for parsing and manipulating database
// schema definitions and migration scripts.
//
// Its primary responsibility is to safely split raw SQL scripts into individual
// statements so they can be executed sequentially by a database driver. The
// parsing logic is designed to be aware of database-specific syntax, such as
// string literals, comments, and dollar-quoted strings in PostgreSQL, to
// prevent false positives when splitting on statement terminators like
// semicolons.
//
// # Usage
//
// Use the provided [Parser] implementations to break down SQL migration files
// into executable chunks.
//
// Example:
//
//	script := []byte("CREATE TABLE users (id int); -- comment\nINSERT INTO users VALUES (1);")
//	statements := schema.Postgres(script)
//	// returns ["CREATE TABLE users (id int)", "INSERT INTO users VALUES (1)"]
package schema

import (
	"bytes"

	"github.com/deep-rent/nexus/internal/ascii"
)

// Parser is a function that splits a raw SQL script into a slice of individual
// executable statements.
//
// Implementations should handle database-specific syntax rules to ensure
// statements are not prematurely split when terminators appear inside quotes or
// comments.
type Parser func(script []byte) []string

// Postgres is a [Parser] implementation tailored for PostgreSQL scripts.
//
// It safely splits the script by semicolons (';'), while strictly ignoring
// semicolons that appear within:
//   - Single-line comments ("-- ...")
//   - Multi-line block comments ("/* ... */"), supporting nested blocks.
//   - Single-quoted string literals ('...')
//   - Double-quoted identifiers ("...")
//   - PostgreSQL dollar-quoted strings ($tag$...$tag$).
//
// To optimize performance, it uses [bytes] package operations to fast-forward
// through recognized blocks and pre-allocates the statement slice based on
// semicolon frequency.
func Postgres(script []byte) []string {
	script = bytes.TrimSpace(script)

	// Early return for empty or whitespace-only scripts
	if len(script) == 0 {
		return nil
	}

	// Pre-allocate slice based on semicolon count to minimize allocations
	n := bytes.Count(script, []byte{';'})
	p := &postgres{
		script: script,
		stmts:  make([]string, 0, n+1),
	}
	return p.parse()
}

// postgres holds the internal state machine for parsing a PostgreSQL script.
type postgres struct {
	// script is the raw SQL script being parsed.
	script []byte
	// i is the current cursor position (byte index) in the script.
	i int
	// start is the byte index where the current statement begins.
	start int
	// stmts is the collected slice of individual statements.
	stmts []string

	// inSingleQuotes is true if the cursor is within a single-quoted string.
	inSingleQuotes bool
	// inDoubleQuotes is true if the cursor is within a double-quoted string.
	inDoubleQuotes bool
	// inComment is true if the cursor is within a single-line comment.
	inComment bool

	// depth tracks the nesting depth of multi-line block comments.
	depth int
	// tag is the active dollar-quote tag (e.g., "$BODY$") when inside one.
	tag []byte
}

// parse iterates through the script, updating the state machine
// and splitting statements when a valid, top-level semicolon is encountered.
func (p *postgres) parse() []string {
	n := len(p.script)
	for p.i < n {
		// 1. Prioritize state checks and fast-forward using bytes operations
		if p.inComment {
			idx := bytes.IndexByte(p.script[p.i:], '\n')
			if idx == -1 {
				p.i = n // EOF
				break
			}
			p.i += idx + 1
			p.inComment = false
			continue

		} else if p.depth > 0 {
			// Fast-forward to next possible block comment boundary
			idx := bytes.IndexAny(p.script[p.i:], "/*")
			if idx == -1 {
				p.i = n // EOF
				break
			}
			p.i += idx
			c := p.script[p.i]
			if c == '/' && p.i+1 < n && p.script[p.i+1] == '*' {
				p.depth++
				p.i++
			} else if c == '*' && p.i+1 < n && p.script[p.i+1] == '/' {
				p.depth--
				p.i++
			}
			p.i++
			continue

		} else if len(p.tag) != 0 {
			// Fast-forward to the exact matching dollar-tag
			idx := bytes.Index(p.script[p.i:], p.tag)
			if idx == -1 {
				p.i = n // EOF
				break
			}
			p.i += idx + len(p.tag)
			p.tag = nil
			continue

		} else if p.inSingleQuotes {
			idx := bytes.IndexByte(p.script[p.i:], '\'')
			if idx == -1 {
				p.i = n // EOF
				break
			}
			p.i += idx
			if p.i+1 < n && p.script[p.i+1] == '\'' {
				p.i += 2 // Skip escaped quote
			} else {
				p.inSingleQuotes = false
				p.i++
			}
			continue

		} else if p.inDoubleQuotes {
			idx := bytes.IndexByte(p.script[p.i:], '"')
			if idx == -1 {
				p.i = n // EOF
				break
			}
			p.i += idx
			if p.i+1 < n && p.script[p.i+1] == '"' {
				p.i += 2 // Skip escaped quote
			} else {
				p.inDoubleQuotes = false
				p.i++
			}
			continue
		}

		// 2. We are in normal SQL text. Fast-forward to the next relevant
		// character.
		idx := bytes.IndexAny(p.script[p.i:], "-/$'\";")
		if idx == -1 {
			p.i = n // No more special characters, jump to end
			break
		}
		p.i += idx
		c := p.script[p.i]

		// 3. Isolated value-based switch for compiler optimization
		switch c {
		case '-':
			if p.i+1 < n && p.script[p.i+1] == '-' {
				p.inComment = true
				p.i++
			}
		case '/':
			if p.i+1 < n && p.script[p.i+1] == '*' {
				p.depth++
				p.i++
			}
		case '$':
			p.dollar(n)
		case '\'':
			p.inSingleQuotes = true
		case '"':
			p.inDoubleQuotes = true
		case ';':
			p.flush()
		}
		p.i++
	}

	// Add the final statement if the script does not end with a semicolon.
	p.flush()
	return p.stmts
}

// dollar scans ahead to parse a PostgreSQL dollar-quote tag (e.g., "$tag$").
//
// It uses [ascii.IsWord] to validate the characters within the tag. If a valid
// tag is found, the state is updated to track this [postgres.tag] block.
func (p *postgres) dollar(n int) {
	end := -1
	for j := p.i + 1; j < n; j++ {
		nc := p.script[j]
		if nc == '$' {
			end = j
			break
		}
		if !ascii.IsWord(rune(nc)) {
			break
		}
	}
	if end != -1 {
		p.tag = p.script[p.i : end+1]
		p.i = end
	}
}

// flush extracts the current statement from the script buffer.
//
// It trims surrounding whitespace using [bytes.TrimSpace]. If the extracted
// statement is not empty, it is appended to the results list. It then advances
// the [postgres.start] pointer.
func (p *postgres) flush() {
	if p.start >= len(p.script) {
		return
	}
	if stmt := bytes.TrimSpace(p.script[p.start:p.i]); len(stmt) != 0 {
		p.stmts = append(p.stmts, string(stmt))
	}
	p.start = p.i + 1
}
