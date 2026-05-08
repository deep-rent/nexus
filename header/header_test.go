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
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deep-rent/nexus/header"
)

type mockRoundTripper struct{ trap *http.Request }

func (t *mockRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	t.trap = r
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("")),
	}, nil
}

var _ http.RoundTripper = (*mockRoundTripper)(nil)

func TestDirectives(t *testing.T) {
	t.Parallel()

	type directive struct {
		k string
		v string
	}

	tests := []struct {
		name string
		give string
		want []directive
	}{
		{
			name: "simple",
			give: "max-age=3600",
			want: []directive{{"max-age", "3600"}},
		},
		{
			name: "multiple",
			give: "no-cache, max-age=3600",
			want: []directive{{"no-cache", ""}, {"max-age", "3600"}},
		},
		{
			name: "with spaces",
			give: "  no-cache ,  max-age = 3600  ",
			want: []directive{{"no-cache", ""}, {"max-age", "3600"}},
		},
		{
			name: "flag only",
			give: "no-cache",
			want: []directive{{"no-cache", ""}},
		},
		{
			name: "empty",
			give: "",
			want: []directive{{"", ""}},
		},
		{
			name: "only comma",
			give: ",",
			want: []directive{{"", ""}, {"", ""}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got []directive
			for k, v := range header.Directives(tt.give) {
				got = append(got, directive{k, v})
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Directives(%q) = %v; want %v", tt.give, got, tt.want)
			}
		})
	}
}

func TestThrottle(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	future, past := now.Add(30*time.Second), now.Add(-30*time.Second)

	tests := []struct {
		name string
		h    http.Header
		now  func() time.Time
		want time.Duration
	}{
		{
			name: "retry-after seconds",
			h:    http.Header{"Retry-After": {"60"}},
			now:  func() time.Time { return now },
			want: 60 * time.Second,
		},
		{
			name: "retry-after http date future",
			h:    http.Header{"Retry-After": {future.Format(http.TimeFormat)}},
			now:  func() time.Time { return now },
			want: 30 * time.Second,
		},
		{
			name: "retry-after http date past",
			h:    http.Header{"Retry-After": {past.Format(http.TimeFormat)}},
			now:  func() time.Time { return now },
			want: 0,
		},
		{
			name: "x-ratelimit-reset future",
			h: http.Header{
				"X-Ratelimit-Remaining": {"0"},
				"X-Ratelimit-Reset":     {strconv.FormatInt(future.Unix(), 10)},
			},
			now:  func() time.Time { return now },
			want: 30 * time.Second,
		},
		{
			name: "x-ratelimit-reset past",
			h: http.Header{
				"X-Ratelimit-Remaining": {"0"},
				"X-Ratelimit-Reset":     {strconv.FormatInt(past.Unix(), 10)},
			},
			now:  func() time.Time { return now },
			want: 0,
		},
		{
			name: "x-ratelimit-remaining not zero",
			h: http.Header{
				"X-Ratelimit-Remaining": {"10"},
				"X-Ratelimit-Reset":     {strconv.FormatInt(future.Unix(), 10)},
			},
			now:  func() time.Time { return now },
			want: 0,
		},
		{
			name: "no headers",
			h:    http.Header{},
			now:  func() time.Time { return now },
			want: 0,
		},
		{
			name: "invalid retry-after",
			h:    http.Header{"Retry-After": {"invalid"}},
			now:  func() time.Time { return now },
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := header.Throttle(tt.h, tt.now)
			diff := got - tt.want
			if diff < 0 {
				diff = -diff
			}

			if diff > time.Second {
				t.Errorf("Throttle(h, now) = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestLifetime(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	future, past := now.Add(60*time.Second), now.Add(-60*time.Second)

	tests := []struct {
		name string
		h    http.Header
		now  func() time.Time
		want time.Duration
	}{
		{
			name: "cache-control max-age",
			h:    http.Header{"Cache-Control": {"max-age=3600"}},
			now:  func() time.Time { return now },
			want: 3600 * time.Second,
		},
		{
			name: "cache-control no-cache",
			h:    http.Header{"Cache-Control": {"no-cache"}},
			now:  func() time.Time { return now },
			want: 0,
		},
		{
			name: "cache-control no-store",
			h:    http.Header{"Cache-Control": {"no-store"}},
			now:  func() time.Time { return now },
			want: 0,
		},
		{
			name: "expires future",
			h:    http.Header{"Expires": {future.Format(http.TimeFormat)}},
			now:  func() time.Time { return now },
			want: 60 * time.Second,
		},
		{
			name: "expires past",
			h:    http.Header{"Expires": {past.Format(http.TimeFormat)}},
			now:  func() time.Time { return now },
			want: 0,
		},
		{
			name: "cache-control takes precedence",
			h: http.Header{
				"Cache-Control": {"max-age=1800"},
				"Expires":       {future.Format(http.TimeFormat)},
			},
			now:  func() time.Time { return now },
			want: 1800 * time.Second,
		},
		{
			name: "no cache headers",
			h:    http.Header{},
			now:  func() time.Time { return now },
			want: 0,
		},
		{
			name: "invalid max-age",
			h:    http.Header{"Cache-Control": {"max-age=invalid"}},
			now:  func() time.Time { return now },
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := header.Lifetime(tt.h, tt.now)
			diff := got - tt.want
			if diff < 0 {
				diff = -diff
			}

			if diff > time.Second {
				t.Errorf("Lifetime(h, now) = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestCredentials(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		h      http.Header
		scheme string
		want   string
	}{
		{
			name:   "basic scheme",
			h:      http.Header{"Authorization": {"Basic foo"}},
			scheme: "basic",
			want:   "foo",
		},
		{
			name:   "bearer scheme",
			h:      http.Header{"Authorization": {"Bearer bar"}},
			scheme: "bearer",
			want:   "bar",
		},
		{
			name:   "case-insensitive scheme",
			h:      http.Header{"Authorization": {"bearer bar"}},
			scheme: "BEARER",
			want:   "bar",
		},
		{
			name:   "mismatched scheme",
			h:      http.Header{"Authorization": {"Digest baz"}},
			scheme: "bearer",
			want:   "",
		},
		{
			name:   "no auth header",
			h:      http.Header{},
			scheme: "basic",
			want:   "",
		},
		{
			name:   "malformed header",
			h:      http.Header{"Authorization": {"Basicfoo"}},
			scheme: "basic",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := header.Credentials(tt.h, tt.scheme); got != tt.want {
				t.Errorf("Credentials(h, %q) = %q; want %q", tt.scheme, got, tt.want)
			}
		})
	}
}

func TestPreferences(t *testing.T) {
	t.Parallel()

	type pref struct {
		k string
		q float64
	}

	tests := []struct {
		name string
		give string
		want []pref
	}{
		{
			name: "simple",
			give: "en, fr",
			want: []pref{{"en", 1.0}, {"fr", 1.0}},
		},
		{
			name: "with q-factors",
			give: "en;q=0.9, fr;q=0.8",
			want: []pref{{"en", 0.9}, {"fr", 0.8}},
		},
		{
			name: "mixed",
			give: "en, fr;q=0.8",
			want: []pref{{"en", 1.0}, {"fr", 0.8}},
		},
		{
			name: "malformed q-factor",
			give: "en;q=invalid",
			want: []pref{{"en", 1.0}},
		},
		{
			name: "bounded from above",
			give: "a;q=2.0",
			want: []pref{{"a", 1.0}},
		},
		{
			name: "bounded from below",
			give: "b;q=-1.0",
			want: []pref{{"b", 0.0}},
		},
		{
			name: "empty",
			give: "",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got []pref
			for k, q := range header.Preferences(tt.give) {
				got = append(got, pref{k, q})
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Preferences(%q) = %v; want %v", tt.give, got, tt.want)
			}
		})
	}
}

func TestAccepts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		key   string
		want  bool
	}{
		{
			name:  "accepted",
			value: "application/json, text/plain;q=0.9",
			key:   "application/json",
			want:  true,
		},
		{
			name:  "rejected with q=0",
			value: "application/json, text/plain;q=0",
			key:   "text/plain",
			want:  false,
		},
		{
			name:  "not present",
			value: "application/json, text/plain",
			key:   "image/png",
			want:  false,
		},
		{
			name:  "global wildcard matching (*/*)",
			value: "application/json, */*;q=0.5",
			key:   "image/png",
			want:  true,
		},
		{
			name:  "global wildcard matching (*)",
			value: "gzip, deflate, *;q=0.5",
			key:   "br",
			want:  true,
		},
		{
			name:  "partial wildcard matching",
			value: "text/*;q=0.8",
			key:   "text/html",
			want:  true,
		},
		{
			name:  "partial wildcard mismatch",
			value: "image/*;q=0.8",
			key:   "text/html",
			want:  false,
		},
		{
			name:  "exact match overrides partial wildcard",
			value: "text/*;q=1.0, text/html;q=0.0",
			key:   "text/html",
			want:  false,
		},
		{
			name:  "exact match overrides global wildcard",
			value: "*/*;q=1.0, text/plain;q=0.0",
			key:   "text/plain",
			want:  false,
		},
		{
			name:  "partial wildcard overrides global wildcard",
			value: "*/*;q=1.0, text/*;q=0.0",
			key:   "text/html",
			want:  false,
		},
		{
			name:  "order independence (exact match first)",
			value: "text/plain;q=0.0, */*;q=1.0",
			key:   "text/plain",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := header.Accepts(tt.value, tt.key); got != tt.want {
				t.Errorf("Accepts(%q, %q) = %t; want %t", tt.value, tt.key, got, tt.want)
			}
		})
	}
}

func TestMediaType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		h    http.Header
		want string
	}{
		{
			name: "basic",
			h:    http.Header{"Content-Type": {"application/json; charset=utf-8"}},
			want: "application/json",
		},
		{
			name: "not present",
			h:    http.Header{},
			want: "",
		},
		{
			name: "empty",
			h:    http.Header{"Content-Type": {""}},
			want: "",
		},
		{
			name: "trim space",
			h:    http.Header{"Content-Type": {" application/json\t"}},
			want: "application/json",
		},
		{
			name: "lowercase",
			h:    http.Header{"Content-Type": {"APPLICATION/JSON; foo=bar"}},
			want: "application/json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := header.MediaType(tt.h); got != tt.want {
				t.Errorf("MediaType(h) = %q; want %q", got, tt.want)
			}
		})
	}
}

func TestLink(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		rel   string
		want  string
	}{
		{
			name:  "single link",
			value: `<https://api.example.com/items?page=2>; rel="next"`,
			rel:   "next",
			want:  "https://api.example.com/items?page=2",
		},
		{
			name: "multiple links finding last",
			value: `<https://api.example.com/items?page=2>; rel="next", ` +
				`<https://api.example.com/items?page=5>; rel="last"`,
			rel:  "last",
			want: "https://api.example.com/items?page=5",
		},
		{
			name: "multiple links finding first",
			value: `<https://api.example.com/items?page=2>; rel="next", ` +
				`<https://api.example.com/items?page=1>; rel="prev"`,
			rel:  "prev",
			want: "https://api.example.com/items?page=1",
		},
		{
			name:  "unquoted relation token",
			value: `<https://api.example.com/items?page=2>; rel=next`,
			rel:   "next",
			want:  "https://api.example.com/items?page=2",
		},
		{
			name:  "multiple space-separated relations in one link",
			value: `<https://api.example.com/items?page=2>; rel="next archive"`,
			rel:   "archive",
			want:  "https://api.example.com/items?page=2",
		},
		{
			name:  "relation not present",
			value: `<https://api.example.com/items?page=2>; rel="next"`,
			rel:   "last",
			want:  "",
		},
		{
			name:  "malformed link without brackets",
			value: `https://api.example.com/items?page=2; rel="next"`,
			rel:   "next",
			want:  "",
		},
		{
			name:  "case insensitive relation lookup",
			value: `<https://api.example.com/items?page=2>; rel="NEXT"`,
			rel:   "next",
			want:  "https://api.example.com/items?page=2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := header.Link(tt.value, tt.rel); got != tt.want {
				t.Errorf("Link(%q, %q) = %q; want %q", tt.value, tt.rel, got, tt.want)
			}
		})
	}
}

func TestLinks(t *testing.T) {
	t.Parallel()

	type linkPair struct {
		rel string
		url string
	}

	tests := []struct {
		name  string
		value string
		want  []linkPair
	}{
		{
			name:  "single link",
			value: `<https://api.example.com/items?page=2>; rel="next"`,
			want: []linkPair{
				{"next", "https://api.example.com/items?page=2"},
			},
		},
		{
			name: "multiple links",
			value: `<https://api.example.com/items?page=2>; rel="next", ` +
				`<https://api.example.com/items?page=5>; rel="last"`,
			want: []linkPair{
				{"next", "https://api.example.com/items?page=2"},
				{"last", "https://api.example.com/items?page=5"},
			},
		},
		{
			name:  "multiple space-separated relations",
			value: `<https://api.example.com/items?page=2>; rel="next archive"`,
			want: []linkPair{
				{"next", "https://api.example.com/items?page=2"},
				{"archive", "https://api.example.com/items?page=2"},
			},
		},
		{
			name:  "unquoted relation token",
			value: `<https://api.example.com/items?page=2>; rel=next`,
			want: []linkPair{
				{"next", "https://api.example.com/items?page=2"},
			},
		},
		{
			name:  "mixed case relation normalization",
			value: `<https://api.example.com/items?page=2>; rel="NEXT"`,
			want: []linkPair{
				{"next", "https://api.example.com/items?page=2"},
			},
		},
		{
			name:  "missing rel parameter",
			value: `<https://api.example.com/items?page=2>; title="Next Page"`,
			want:  nil,
		},
		{
			name:  "malformed without brackets",
			value: `https://api.example.com/items?page=2; rel="next"`,
			want:  nil,
		},
		{
			name:  "empty string",
			value: "",
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got []linkPair
			for rel, url := range header.Links(tt.value) {
				got = append(got, linkPair{rel: rel, url: url})
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Links(%q) = %v; want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestFilename(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		h    http.Header
		want string
	}{
		{
			name: "standard filename",
			h: http.Header{
				"Content-Disposition": []string{`attachment; filename="foo.pdf"`},
			},
			want: "foo.pdf",
		},
		{
			name: "unquoted filename",
			h: http.Header{
				"Content-Disposition": []string{`attachment; filename=bar.pdf`},
			},
			want: "bar.pdf",
		},
		{
			name: "utf-8 filename (RFC 6266)",
			h: http.Header{
				"Content-Disposition": []string{
					`attachment; filename*=UTF-8''%e2%82%ac%20foo.pdf`,
				},
			},
			want: "€ foo.pdf",
		},
		{
			name: "fallback with both filename and filename*",
			h: http.Header{
				"Content-Disposition": []string{
					`attachment;filename="bar.pdf";filename*=UTF-8''%e2%82%ac%20bar.pdf`,
				},
			},
			want: "€ bar.pdf",
		},
		{
			name: "no filename present",
			h:    http.Header{"Content-Disposition": []string{`inline`}},
			want: "",
		},
		{
			name: "empty header",
			h:    http.Header{},
			want: "",
		},
		{
			name: "malformed header",
			h: http.Header{
				"Content-Disposition": []string{
					`attachment; filename="missing-quote.pdf`,
				},
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := header.Filename(tt.h); got != tt.want {
				t.Errorf("Filename(h) = %q; want %q", got, tt.want)
			}
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	h := header.New("x-foo-bar", "baz")

	if h.Key != "X-Foo-Bar" {
		t.Errorf("h.Key = %q; want %q", h.Key, "X-Foo-Bar")
	}

	if h.Value != "baz" {
		t.Errorf("h.Value = %q; want %q", h.Value, "baz")
	}

	if got, want := h.String(), "X-Foo-Bar: baz"; got != want {
		t.Errorf("h.String() = %q; want %q", got, want)
	}
}

func TestUserAgent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		product string
		version string
		comment string
		want    string
	}{
		{
			name:    "UserAgent",
			product: "foobar",
			version: "1.0",
			comment: "contact@example.com",
			want:    "foobar/1.0 (contact@example.com)",
		},
		{
			name:    "UserAgent without comment",
			product: "foobar",
			version: "1.0",
			comment: "",
			want:    "foobar/1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := header.UserAgent(tt.product, tt.version, tt.comment)
			if h.Key != "User-Agent" {
				t.Errorf("h.Key = %q; want %q", h.Key, "User-Agent")
			}

			if h.Value != tt.want {
				t.Errorf("h.Value = %q; want %q", h.Value, tt.want)
			}
		})
	}
}

func TestNewTransport(t *testing.T) {
	t.Parallel()

	t.Run("no headers returns original transport", func(t *testing.T) {
		t.Parallel()

		base := http.DefaultTransport
		wrapped := header.NewTransport(base)

		if base != wrapped {
			t.Errorf("NewTransport(base) = %p; want %p", wrapped, base)
		}
	})

	t.Run("adds headers to request", func(t *testing.T) {
		t.Parallel()

		req, err := http.NewRequestWithContext(
			t.Context(),
			"GET",
			"http://example.com",
			nil,
		)
		if err != nil {
			t.Fatalf("http.NewRequestWithContext() = %v", err)
		}

		originalHeader := req.Header.Clone()
		base := &mockRoundTripper{}

		headers := []header.Header{
			header.New("X-Foo", "foo"),
			header.New("X-Bar", "bar"),
		}
		transport := header.NewTransport(base, headers...)

		_, err = transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("transport.RoundTrip(req) = %v; want nil", err)
		}

		r := base.trap
		if r == nil {
			t.Fatal("base.trap = nil; want *http.Request")
		}

		if r == req {
			t.Error("request should have been cloned but was same instance")
		}

		if got := r.Header.Get("X-Foo"); got != "foo" {
			t.Errorf("r.Header.Get(\"X-Foo\") = %q; want %q", got, "foo")
		}

		if got := r.Header.Get("X-Bar"); got != "bar" {
			t.Errorf("r.Header.Get(\"X-Bar\") = %q; want %q", got, "bar")
		}

		if !reflect.DeepEqual(req.Header, originalHeader) {
			t.Errorf("req.Header = %v; want %v (original should be untouched)",
				req.Header, originalHeader)
		}
	})
}
