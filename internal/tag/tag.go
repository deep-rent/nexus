package tag

import (
	"iter"
	"strings"
	"unicode"

	"github.com/deep-rent/nexus/internal/quote"
)

type Tag struct {
	Name string
	opts string
}

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

func Parse(s string) *Tag {
	name, opts, _ := strings.Cut(s, ",")
	return &Tag{
		Name: name,
		opts: opts,
	}
}
