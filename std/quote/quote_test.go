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

package quote_test

import (
	"testing"

	"github.com/deep-rent/nexus/std/quote"
)

func TestRemove(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want string
	}{
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := quote.Remove(tt.give); got != tt.want {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}
}

func TestRemoveAll(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want string
	}{
		{"single layer double", `"hello"`, "hello"},
		{"single layer single", `'hello'`, "hello"},
		{"nested mixed quotes", `"'hello'"`, "hello"},
		{"deeply nested mixed quotes", `'"'"hello"'"'`, "hello"},
		{"nested same quotes", `""hello""`, "hello"},
		{"unmatched inner quote", `"he'llo"`, "he'llo"},
		{"mismatched outer layer", `"hello'`, `"hello'`},
		{"no quotes", "hello", "hello"},
		{"empty string", "", ""},
		{"only quotes stripped to empty", `""''""`, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := quote.RemoveAll(tt.give); got != tt.want {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}
}

func TestHas(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want bool
	}{
		{"double quoted", `"hello"`, true},
		{"single quoted", `'hello'`, true},
		{"empty double quotes", `""`, true},
		{"empty single quotes", `''`, true},
		{"mismatched quotes", `"hello'`, false},
		{"missing end quote", `"hello`, false},
		{"missing start quote", `hello"`, false},
		{"no quotes", `hello`, false},
		{"single char", `"`, false},
		{"empty string", ``, false},
		{"quote inside", `he"llo`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := quote.Has(tt.give); got != tt.want {
				t.Errorf("got %v; want %v", got, tt.want)
			}
		})
	}
}

func TestDouble(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want string
	}{
		{"standard string", "hello", `"hello"`},
		{"empty string", "", `""`},
		{"string with spaces", "hello world", `"hello world"`},
		{"string already double quoted", `"hello"`, `""hello""`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := quote.Double(tt.give); got != tt.want {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}
}

func TestSingle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want string
	}{
		{"standard string", "hello", `'hello'`},
		{"empty string", "", `''`},
		{"string with spaces", "hello world", `'hello world'`},
		{"string already single quoted", `'hello'`, `''hello''`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := quote.Single(tt.give); got != tt.want {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}
}

func TestEscape(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want string
	}{
		{"plain identifier", "users", `"users"`},
		{"empty string", "", `""`},
		{"embedded double quote", `we"ird`, `"we""ird"`},
		{"only double quotes", `""`, `""""""`},
		{"single quote untouched", "it's", `"it's"`},
		{"spaces preserved", "my table", `"my table"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := quote.Escape(tt.give); got != tt.want {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}
}

func TestIdent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give []string
		want string
	}{
		{"single part", []string{"users"}, `"users"`},
		{"schema and table", []string{"public", "users"}, `"public"."users"`},
		{
			"three parts",
			[]string{"db", "public", "users"},
			`"db"."public"."users"`,
		},
		{
			"embedded double quote",
			[]string{`pub"lic`, "users"},
			`"pub""lic"."users"`,
		},
		{"empty part", []string{"public", ""}, `"public".""`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := quote.Ident(tt.give...); got != tt.want {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}
}

func TestIdent_PanicsOnEmptyParts(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("ident without parts: should have panicked")
		}
	}()
	quote.Ident()
}

func TestLiteral(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want string
	}{
		{"plain string", "hello", `'hello'`},
		{"empty string", "", `''`},
		{"embedded single quote", "it's", `'it''s'`},
		{"only single quotes", `''`, `''''''`},
		{"double quote untouched", `he said "hi"`, `'he said "hi"'`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := quote.Literal(tt.give); got != tt.want {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}
}
