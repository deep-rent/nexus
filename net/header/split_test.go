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

package header_test

import (
	"maps"
	"testing"

	"github.com/deep-rent/nexus/net/header"
)

// A comma inside the angle brackets belongs to the link target.
func TestLink_CommaInURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		rel  string
		want string
	}{
		{
			name: "comma in query string",
			give: `<https://example.com/items?ids=1,2,3&page=2>; rel="next"`,
			rel:  "next",
			want: "https://example.com/items?ids=1,2,3&page=2",
		},
		{
			name: "comma in path",
			give: `<https://example.com/a,b/c>; rel="self"`,
			rel:  "self",
			want: "https://example.com/a,b/c",
		},
		{
			name: "several links, one with a comma",
			give: `<https://example.com/p?ids=1,2>; rel="next", ` +
				`<https://example.com/p?ids=9>; rel="last"`,
			rel:  "last",
			want: "https://example.com/p?ids=9",
		},
		{
			name: "comma in a quoted parameter",
			give: `<https://example.com/p>; title="a, b"; rel="next"`,
			rel:  "next",
			want: "https://example.com/p",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := header.Link(tt.give, tt.rel); got != tt.want {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}
}

// A link whose target contains a comma must not swallow the links beside it.
func TestLinks_CommaInURL(t *testing.T) {
	t.Parallel()

	give := `<https://example.com/p?ids=1,2>; rel="next", ` +
		`<https://example.com/p?ids=3,4>; rel="prev"`

	want := map[string]string{
		"next": "https://example.com/p?ids=1,2",
		"prev": "https://example.com/p?ids=3,4",
	}

	got := maps.Collect(header.Links(give))

	if !maps.Equal(got, want) {
		t.Errorf("got %v; want %v", got, want)
	}
}

// A quoted directive value may contain the list separator.
func TestDirectives_QuotedValues(t *testing.T) {
	t.Parallel()

	type directive struct{ k, v string }

	tests := []struct {
		name string
		give string
		want []directive
	}{
		{
			name: "comma inside quotes",
			give: `no-cache="Set-Cookie, Authorization", max-age=60`,
			want: []directive{
				{"no-cache", "Set-Cookie, Authorization"},
				{"max-age", "60"},
			},
		},
		{
			name: "quoted number",
			give: `max-age="3600"`,
			want: []directive{{"max-age", "3600"}},
		},
		{
			name: "escaped quote",
			give: `private="a\"b"`,
			want: []directive{{"private", `a"b`}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got []directive
			for k, v := range header.Directives(tt.give) {
				got = append(got, directive{k, v})
			}

			if len(got) != len(tt.want) {
				t.Fatalf("got %v; want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("got %v; want %v", got, tt.want)
					return
				}
			}
		})
	}
}

// A quoted parameter must not split a preference list.
func TestPreferences_QuotedValues(t *testing.T) {
	t.Parallel()

	give := `text/html;level="1,2";q=0.8, text/plain`

	want := map[string]float64{
		"text/html":  0.8,
		"text/plain": 1.0,
	}

	got := maps.Collect(header.Preferences(give))

	if !maps.Equal(got, want) {
		t.Errorf("got %v; want %v", got, want)
	}
}
