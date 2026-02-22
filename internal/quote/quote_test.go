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
