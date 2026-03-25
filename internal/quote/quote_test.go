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

	"github.com/stretchr/testify/assert"

	"github.com/deep-rent/nexus/internal/quote"
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

func TestRemoveAll(t *testing.T) {
	type test struct {
		name string
		in   string
		want string
	}

	tests := []test{
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

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := quote.RemoveAll(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestHas(t *testing.T) {
	type test struct {
		name string
		in   string
		want bool
	}

	tests := []test{
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

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := quote.Has(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestWrap(t *testing.T) {
	type test struct {
		name string
		in   string
		q    rune
		want string
	}

	tests := []test{
		{"wrap with double quote", "hello", '"', `"hello"`},
		{"wrap with single quote", "world", '\'', `'world'`},
		{"wrap empty string", "", '"', `""`},
		{"wrap with arbitrary rune", "test", '|', `|test|`},
		{"wrap string already containing quotes", `"hello"`, '\'', `'"hello"'`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := quote.Wrap(tc.in, tc.q)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestDouble(t *testing.T) {
	type test struct {
		name string
		in   string
		want string
	}

	tests := []test{
		{"standard string", "hello", `"hello"`},
		{"empty string", "", `""`},
		{"string with spaces", "hello world", `"hello world"`},
		{"string already double quoted", `"hello"`, `""hello""`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := quote.Double(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestSingle(t *testing.T) {
	type test struct {
		name string
		in   string
		want string
	}

	tests := []test{
		{"standard string", "hello", `'hello'`},
		{"empty string", "", `''`},
		{"string with spaces", "hello world", `'hello world'`},
		{"string already single quoted", `'hello'`, `''hello''`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := quote.Single(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}
