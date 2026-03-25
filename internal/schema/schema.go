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
// statements so they can be executed sequentially by a database driver.
// The parsing logic is designed to be aware of database-specific syntax,
// such as string literals, comments, and dollar-quoted strings in PostgreSQL,
// to prevent false positives when splitting on statement terminators like
// semicolons.
package schema

import (
	"bytes"

	"github.com/deep-rent/nexus/internal/ascii"
)

// Parser is a function that splits a raw SQL script into a slice of individual
// executable statements. Implementations should handle database-specific syntax
// rules to ensure statements are not prematurely split.
type Parser func(script []byte) []string

// Postgres is a Parser implementation tailored for PostgreSQL scripts.
// It safely splits the script by semicolons (';'), while strictly ignoring
// semicolons that appear within:
//   - Single-line comments ("-- ...")
//   - Multi-line block comments ("/* ... */"), supporting nested blocks.
//   - Single-quoted string literals ('...')
//   - Double-quoted identifiers ("...")
//   - PostgreSQL dollar-quoted strings ($tag$...$tag$).
func Postgres(script []byte) []string {
	p := &postgres{script: script}
	return p.parse()
}

// postgres holds the internal state machine for parsing a PostgreSQL script.
type postgres struct {
	script []byte   // The raw SQL script being parsed.
	i      int      // The current cursor position (byte index) in the script.
	start  int      // The byte index where the current statement begins.
	stmts  []string // The collected slice of individual statements.

	inSingleQuotes bool // True if the cursor is within a single-quoted string.
	inDoubleQuotes bool // True if the cursor is within a double-quoted string.
	inComment      bool // True if the cursor is within a single-line comment.

	// Tracks the nesting depth of multi-line block comments.
	blockCommentDepth int

	// The active dollar-quote tag (e.g., "$BODY$") if currently inside one.
	dollarQuoteTag []byte
}

// parse iterates through the script byte-by-byte, updating the state machine
// and splitting statements when a valid, top-level semicolon is encountered.
func (p *postgres) parse() []string {
	n := len(p.script)
	for p.i < n {
		c := p.script[p.i]

		// The order of checks is important. Mutually exclusive states are processed
		// in a strict priority to correctly handle nesting (e.g., a quote inside a
		// comment).
		switch {
		case p.inComment:
			if c == '\n' {
				p.inComment = false
			}
		case p.blockCommentDepth > 0:
			if c == '/' && p.i+1 < n && p.script[p.i+1] == '*' {
				p.blockCommentDepth++
				p.i++
			} else if c == '*' && p.i+1 < n && p.script[p.i+1] == '/' {
				p.blockCommentDepth--
				p.i++
			}
		case len(p.dollarQuoteTag) > 0:
			if c == '$' && bytes.HasPrefix(p.script[p.i:], p.dollarQuoteTag) {
				p.i += len(p.dollarQuoteTag) - 1
				p.dollarQuoteTag = nil
			}
		case p.inSingleQuotes:
			if c == '\'' {
				if p.i+1 < n && p.script[p.i+1] == '\'' {
					p.i++ // Skip escaped quote
				} else {
					p.inSingleQuotes = false
				}
			}
		case p.inDoubleQuotes:
			if c == '"' {
				if p.i+1 < n && p.script[p.i+1] == '"' {
					p.i++ // Skip escaped quote
				} else {
					p.inDoubleQuotes = false
				}
			}
		case c == '-' && p.i+1 < n && p.script[p.i+1] == '-':
			p.inComment = true
			p.i++
		case c == '/' && p.i+1 < n && p.script[p.i+1] == '*':
			p.blockCommentDepth++
			p.i++
		case c == '$':
			p.dollar(n)
		case c == '\'':
			p.inSingleQuotes = true
		case c == '"':
			p.inDoubleQuotes = true
		case c == ';':
			p.flush()
		}
		p.i++
	}

	// Add the last statement if the script does not end with a semicolon.
	p.flush()
	return p.stmts
}

// dollar scans ahead to parse a PostgreSQL dollar-quote tag (e.g., "$tag$").
// If a valid tag is found, it updates the state to track the active
// dollar-quote.
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
		p.dollarQuoteTag = p.script[p.i : end+1]
		p.i = end
	}
}

// flush extracts the current statement from the script buffer, trims any
// surrounding whitespace, and appends it to the results list if it is not
// empty. It then advances the start index to prepare for the next statement.
func (p *postgres) flush() {
	if stmt := bytes.TrimSpace(p.script[p.start:p.i]); len(stmt) > 0 {
		p.stmts = append(p.stmts, string(stmt))
	}
	p.start = p.i + 1
}
