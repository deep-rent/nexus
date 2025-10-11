package quote_test

import (
	"testing"

	"github.com/deep-rent/nexus/internal/quote"
	"github.com/stretchr/testify/assert"
)

func TestRemove(t *testing.T) {
	type test struct {
		name string
		in   string
		want string
	}

	tests := []test{
		{"double quotes", `"hello"`, "hello"},
		{"single quotes", "'world'", "world"},
		{"no quotes", "no change", "no change"},
		{"empty string", "", ""},
		{"single char", "a", "a"},
		{"only quotes", `""`, ""},
		{"only single quotes", `''`, ""},
		{"mismatched quotes start", `"hello'`, `"hello'`},
		{"mismatched quotes end", `'hello"`, `'hello"`},
		{"mixed quotes", `'"'`, `"`},
		{"quote in middle", `he"llo`, `he"llo`},
		{"only start quote", `"hello`, `"hello`},
		{"only end quote", `hello"`, `hello"`},
		{"short string with quote", `"`, `"`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := quote.Remove(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}
