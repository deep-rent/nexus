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
	"bytes"

	"github.com/deep-rent/nexus/internal/ascii"
)

// Parser is a function that splits a SQL script into individual statements.
type Parser func(script []byte) []string

// Postgres splits a PostgreSQL script into individual statements.
// It safely splits by semicolons while ignoring those within comments,
// string literals, identifiers, and PostgreSQL dollar quotes.
// It also allows splitting by a custom delimiter "-- nexus:split".
func Postgres(script []byte) []string {
	delim := []byte("-- nexus:split")
	if bytes.Contains(script, delim) {
		var stmts []string
		for s := range bytes.SplitSeq(script, delim) {
			if t := bytes.TrimSpace(s); len(t) > 0 {
				stmts = append(stmts, string(t))
			}
		}
		return stmts
	}

	p := &postgres{script: script}
	return p.parse()
}

// postgres holds the state for parsing a SQL script.
type postgres struct {
	script []byte
	pos    int
	start  int
	stmts  []string

	inSingleQuotes    bool
	inDoubleQuotes    bool
	inLineComment     bool
	blockCommentDepth int
	dollarQuoteTag    []byte
}

func (p *postgres) parse() []string {
	n := len(p.script)
	for p.pos < n {
		c := p.script[p.pos]

		// The order of checks is important.
		switch {
		case p.inLineComment:
			if c == '\n' {
				p.inLineComment = false
			}
		case p.blockCommentDepth > 0:
			if c == '/' && p.pos+1 < n && p.script[p.pos+1] == '*' {
				p.blockCommentDepth++
				p.pos++
			} else if c == '*' && p.pos+1 < n && p.script[p.pos+1] == '/' {
				p.blockCommentDepth--
				p.pos++
			}
		case len(p.dollarQuoteTag) > 0:
			if c == '$' && bytes.HasPrefix(p.script[p.pos:], p.dollarQuoteTag) {
				p.pos += len(p.dollarQuoteTag) - 1
				p.dollarQuoteTag = nil
			}
		case p.inSingleQuotes:
			if c == '\'' {
				if p.pos+1 < n && p.script[p.pos+1] == '\'' {
					p.pos++ // Skip escaped quote
				} else {
					p.inSingleQuotes = false
				}
			}
		case p.inDoubleQuotes:
			if c == '"' {
				if p.pos+1 < n && p.script[p.pos+1] == '"' {
					p.pos++ // Skip escaped quote
				} else {
					p.inDoubleQuotes = false
				}
			}
		case c == '-' && p.pos+1 < n && p.script[p.pos+1] == '-':
			p.inLineComment = true
			p.pos++
		case c == '/' && p.pos+1 < n && p.script[p.pos+1] == '*':
			p.blockCommentDepth++
			p.pos++
		case c == '$':
			p.scanDollarQuote(n)
		case c == '\'':
			p.inSingleQuotes = true
		case c == '"':
			p.inDoubleQuotes = true
		case c == ';':
			p.flush()
		}
		p.pos++
	}

	p.flush() // Add the last statement if it's not terminated by a semicolon.
	return p.stmts
}

func (p *postgres) scanDollarQuote(n int) {
	end := -1
	for j := p.pos + 1; j < n; j++ {
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
		p.dollarQuoteTag = p.script[p.pos : end+1]
		p.pos = end
	}
}

func (p *postgres) flush() {
	if stmt := bytes.TrimSpace(p.script[p.start:p.pos]); len(stmt) > 0 {
		p.stmts = append(p.stmts, string(stmt))
	}
	p.start = p.pos + 1
}
