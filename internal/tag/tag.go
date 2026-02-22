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

// Package tag provides utility for parsing Go struct tags that follow a
// comma-separated key-value option format, similar to the `json` tag known from
// the standard library.
package tag

import (
	"iter"
	"strings"
	"unicode"

	"github.com/deep-rent/nexus/internal/quote"
)

// Tag represents a parsed struct tag, separating the primary name from the
// additional options.
type Tag struct {
	Name string
	opts string
}

// Opts returns an iterator sequence over the tag's options.
//
// Each element yielded is a key-value pair. If an option does not have an
// explicit value (e.g., "omitempty"), the value string will be empty. Keys and
// values are trimmed of surrounding whitespace. Values that were quoted in the
// source string (e.g., `key:"value"`) will have the quotes removed. Commas
// inside quoted values are preserved and not treated as option separators
// (e.g., `key:"val1,val2"` is one option).
func (t *Tag) Opts() iter.Seq2[string, string] {
	return func(yield func(string, string) bool) {
		rest := t.opts
		// Scan through the rest of the string until it's completely consumed.
		for rest != "" {
			// Trim leading space from the rest of the string.
			rest = strings.TrimLeftFunc(rest, unicode.IsSpace)
			if rest == "" {
				break
			}

			// Find the end of the current option part by finding the next
			// comma that is not inside quotes.
			end := -1
			inQuote := false
			var q rune
			for i, r := range rest {
				if r == q {
					inQuote = false
					q = 0
				} else if !inQuote && (r == '\'' || r == '"') {
					inQuote = true
					q = r
				} else if !inQuote && r == ',' {
					end = i
					break
				}
			}

			var part string
			if end == -1 {
				// This is the last option part.
				part = rest
				rest = ""
			} else {
				part = rest[:end]
				rest = rest[end+1:]
			}

			// Now, parse the individual part (e.g., "default:'foo,bar'").
			k, v, found := strings.Cut(part, ":")
			if found {
				v = quote.Remove(v)
			}
			if !yield(strings.TrimRightFunc(k, unicode.IsSpace), v) {
				return
			}
		}
	}
}

// Parse takes a raw tag string (e.g., `json:opt1,opt2:val`) and separates it
// into the primary name and the options string.
func Parse(s string) *Tag {
	name, opts, _ := strings.Cut(s, ",")
	return &Tag{
		Name: name,
		opts: opts,
	}
}
