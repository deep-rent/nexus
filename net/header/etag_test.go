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
	"net/http"
	"testing"

	"github.com/deep-rent/nexus/net/header"
)

func TestMatchETag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		tag   string
		want  bool
	}{
		{"exact", `"v1"`, `"v1"`, true},
		{"mismatch", `"v2"`, `"v1"`, false},
		{"wildcard", "*", `"v1"`, true},
		{"wildcard padded", "  *  ", `"v1"`, true},
		{"weak candidate", `W/"v1"`, `"v1"`, true},
		{"weak tag", `"v1"`, `W/"v1"`, true},
		{"weak both", `W/"v1"`, `W/"v1"`, true},
		{"list, first", `"v1", "v2"`, `"v1"`, true},
		{"list, last", `"v1", "v2"`, `"v2"`, true},
		{"list, absent", `"v1", "v2"`, `"v3"`, false},
		{"list, spaced", `  "v1" ,  "v2" `, `"v2"`, true},
		{"list, weak", `W/"v1", W/"v2"`, `"v2"`, true},
		{"empty header", "", `"v1"`, false},
		{"blank header", "   ", `"v1"`, false},
		{"empty tag", `"v1"`, "", false},
		// The quotes are part of the tag, so an unquoted value must not
		// match a quoted one.
		{"unquoted", `v1`, `"v1"`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := header.MatchETag(tt.value, tt.tag); got != tt.want {
				t.Errorf("got %t; want %t", got, tt.want)
			}
		})
	}
}

func TestQuote(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want string
	}{
		{"bare", "v1", `"v1"`},
		{"number", "1752000000", `"1752000000"`},
		{"already quoted", `"v1"`, `"v1"`},
		{"weak", `W/"v1"`, `W/"v1"`},
		{"padded", "  v1  ", `"v1"`},
		{"empty", "", ""},
		{"blank", "   ", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := header.Quote(tt.give); got != tt.want {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}
}

// A quoted tag must round-trip through the header and still match.
func TestETag_RoundTrip(t *testing.T) {
	t.Parallel()

	h := http.Header{}
	tag := header.Quote("1752000000")
	h.Set("ETag", tag)

	if got := header.ETag(h); got != tag {
		t.Errorf("got %q; want %q", got, tag)
	}

	if !header.MatchETag(header.ETag(h), tag) {
		t.Error("a tag read back from the header did not match itself")
	}
}

func TestETag_Missing(t *testing.T) {
	t.Parallel()

	if got := header.ETag(http.Header{}); got != "" {
		t.Errorf("got %q; want empty", got)
	}
}
