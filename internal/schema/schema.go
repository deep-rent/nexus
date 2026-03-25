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

	p := &postgresParser{script: script}
	return p.parse()
}

// postgresParser holds the state for parsing a SQL script.
type postgresParser struct {
	script string
	pos    int
	start  int
	stmts  []string

	inSingleQuotes    bool
	inDoubleQuotes    bool
	inLineComment     bool
	blockCommentDepth int
	dollarQuoteTag    string
}

func (p *postgresParser) parse() []string {
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
		case p.dollarQuoteTag != "":
			if c == '$' && strings.HasPrefix(p.script[p.pos:], p.dollarQuoteTag) {
				p.pos += len(p.dollarQuoteTag) - 1
				p.dollarQuoteTag = ""
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

func (p *postgresParser) scanDollarQuote(n int) {
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

func (p *postgresParser) flush() {
	if stmt := strings.TrimSpace(p.script[p.start:p.pos]); stmt != "" {
		p.stmts = append(p.stmts, stmt)
	}
	p.start = p.pos + 1
}
