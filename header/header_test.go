package header_test

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deep-rent/nexus/header"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDirectives(t *testing.T) {
	type test struct {
		name string
		in   string
		want []header.Directive
	}
	tests := []test{
		{
			name: "simple",
			in:   "max-age=3600",
			want: []header.Directive{{"max-age", "3600"}},
		},
		{
			name: "multiple",
			in:   "no-cache, max-age=3600",
			want: []header.Directive{{"no-cache", ""}, {"max-age", "3600"}},
		},
		{
			name: "with spaces",
			in:   "  no-cache ,  max-age = 3600  ",
			want: []header.Directive{{"no-cache", ""}, {"max-age", "3600"}},
		},
		{
			name: "flag only",
			in:   "no-cache",
			want: []header.Directive{{"no-cache", ""}},
		},
		{
			name: "empty",
			in:   "",
			want: []header.Directive{{"", ""}},
		},
		{
			name: "only comma",
			in:   ",",
			want: []header.Directive{{"", ""}, {"", ""}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got []header.Directive
			for d := range header.Directives(tc.in) {
				got = append(got, d)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestThrottle(t *testing.T) {
	now := time.Now().UTC()
	future, past := now.Add(30*time.Second), now.Add(-30*time.Second)

	type test struct {
		name string
		h    http.Header
		now  func() time.Time
		want time.Duration
	}

	tests := []test{
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

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := header.Throttle(tc.h, tc.now)
			assert.InDelta(t, tc.want, got, float64(time.Second))
		})
	}
}

func TestLifetime(t *testing.T) {
	now := time.Now().UTC()
	future, past := now.Add(60*time.Second), now.Add(-60*time.Second)

	type test struct {
		name string
		h    http.Header
		now  func() time.Time
		want time.Duration
	}
	tests := []test{
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

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := header.Lifetime(tc.h, tc.now)
			assert.InDelta(t, tc.want, got, float64(time.Second))
		})
	}
}

func TestCredentials(t *testing.T) {
	type test struct {
		name   string
		h      http.Header
		scheme string
		want   string
	}
	tests := []test{
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
			scheme: "bearer",
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

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := header.Credentials(tc.h, tc.scheme)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestPreferences(t *testing.T) {
	type pref struct {
		k string
		q float64
	}
	type test struct {
		name string
		in   string
		want []pref
	}
	tests := []test{
		{
			name: "simple",
			in:   "en, fr",
			want: []pref{{"en", 1.0}, {"fr", 1.0}},
		},
		{
			name: "with q-factors",
			in:   "en;q=0.9, fr;q=0.8",
			want: []pref{{"en", 0.9}, {"fr", 0.8}},
		},
		{
			name: "mixed",
			in:   "en, fr;q=0.8",
			want: []pref{{"en", 1.0}, {"fr", 0.8}},
		},
		{
			name: "malformed q-factor",
			in:   "en;q=invalid",
			want: []pref{{"en", 1.0}},
		},
		{
			name: "empty",
			in:   "",
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got []pref
			for k, q := range header.Preferences(tc.in) {
				got = append(got, pref{k, q})
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestAccepts(t *testing.T) {
	type test struct {
		name  string
		value string
		key   string
		want  bool
	}
	tests := []test{
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
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := header.Accepts(tc.value, tc.key)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestNew(t *testing.T) {
	h := header.New("x-foo-bar", "baz")
	assert.Equal(t, "X-Foo-Bar", h.Key)
	assert.Equal(t, "baz", h.Value)
	assert.Equal(t, "X-Foo-Bar: baz", h.String())
}

func TestUserAgent(t *testing.T) {
	t.Run("UserAgent", func(t *testing.T) {
		h := header.UserAgent("foobar", "1.0", "contact@example.com")
		assert.Equal(t, "User-Agent", h.Key)
		assert.Equal(t, "foobar/1.0 (contact@example.com)", h.Value)
	})

	t.Run("UserAgent without comment", func(t *testing.T) {
		h := header.UserAgent("foobar", "1.0", "")
		assert.Equal(t, "User-Agent", h.Key)
		assert.Equal(t, "foobar/1.0", h.Value)
	})
}

type mockRoundTripper struct{ trap *http.Request }

func (t *mockRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	t.trap = r
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("")),
	}, nil
}

var _ http.RoundTripper = (*mockRoundTripper)(nil)

func TestNewTransport(t *testing.T) {
	t.Run("no headers returns original transport", func(t *testing.T) {
		base := http.DefaultTransport
		wrapped := header.NewTransport(base)
		assert.Same(t, base, wrapped)
	})

	t.Run("adds headers to request", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		originalHeader := req.Header.Clone()
		base := &mockRoundTripper{}

		headers := []header.Header{
			header.New("X-Foo", "foo"),
			header.New("X-Bar", "bar"),
		}
		transport := header.NewTransport(base, headers...)

		_, err := transport.RoundTrip(req)
		require.NoError(t, err)

		r := base.trap
		assert.NotNil(t, r)
		assert.NotSame(t, req, r, "request should have been cloned")
		assert.Equal(t, "foo", r.Header.Get("X-Foo"))
		assert.Equal(t, "bar", r.Header.Get("X-Bar"))
		assert.Equal(t, originalHeader, req.Header)
	})
}
