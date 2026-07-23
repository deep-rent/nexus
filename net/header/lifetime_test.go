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
	"time"

	"github.com/deep-rent/nexus/net/header"
	"github.com/deep-rent/nexus/std/clock"
)

// A directive that forbids caching must win no matter where it appears.
func TestLifetime_DirectiveOrder(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want time.Duration
	}{
		{"no-store first", "no-store, max-age=3600", 0},
		{"no-store last", "max-age=3600, no-store", 0},
		{"no-cache first", "no-cache, max-age=3600", 0},
		{"no-cache last", "max-age=3600, no-cache", 0},
		{"no-store among many", "public, max-age=3600, no-store", 0},
		{"cacheable", "public, max-age=3600", time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := http.Header{"Cache-Control": []string{tt.give}}
			if got := header.Lifetime(h, time.Now); got != tt.want {
				t.Errorf("got %v; want %v", got, tt.want)
			}
		})
	}
}

// A no-cache that names fields is not a blanket prohibition.
func TestLifetime_QualifiedNoCache(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want time.Duration
	}{
		{
			"qualified",
			`no-cache="Set-Cookie", max-age=3600`,
			time.Hour,
		},
		{
			"qualified, several fields",
			`max-age=60, no-cache="Set-Cookie, Authorization"`,
			time.Minute,
		},
		{"unqualified", "no-cache, max-age=3600", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := http.Header{"Cache-Control": []string{tt.give}}
			if got := header.Lifetime(h, time.Now); got != tt.want {
				t.Errorf("got %v; want %v", got, tt.want)
			}
		})
	}
}

// Cache-Control without a max-age still defers to Expires.
func TestLifetime_FallsBackToExpires(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)

	h := http.Header{
		"Cache-Control": []string{"public"},
		"Expires":       []string{now.Add(time.Hour).Format(http.TimeFormat)},
	}

	if got, want := header.Lifetime(h, clock.Frozen(now)), time.Hour; got != want {
		t.Errorf("got %v; want %v", got, want)
	}
}

// The documented contract is a non-negative duration.
func TestLifetime_NeverNegative(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		h    http.Header
	}{
		{
			"negative max-age",
			http.Header{"Cache-Control": []string{"max-age=-3600"}},
		},
		{
			"max-age of minus one",
			http.Header{"Cache-Control": []string{"max-age=-1"}},
		},
		{
			"expires in the past",
			http.Header{"Expires": []string{
				time.Now().Add(-time.Hour).Format(http.TimeFormat),
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := header.Lifetime(tt.h, time.Now); got < 0 {
				t.Errorf("got %v; want a non-negative duration", got)
			}
		})
	}
}

// A response relayed by an upstream cache has only its remaining age budget.
func TestLifetime_SubtractsAge(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		age  string
		want time.Duration
	}{
		{"no age header", "", time.Hour},
		{"partially aged", "3540", time.Minute},
		{"fully aged", "3600", 0},
		{"aged beyond max-age", "7200", 0},
		{"malformed age", "soon", time.Hour},
		{"negative age", "-60", time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := http.Header{"Cache-Control": []string{"max-age=3600"}}
			if tt.age != "" {
				h.Set("Age", tt.age)
			}

			if got := header.Lifetime(h, time.Now); got != tt.want {
				t.Errorf("got %v; want %v", got, tt.want)
			}
		})
	}
}

// Expires names an absolute instant, so it is measured against the clock and
// must not be reduced by Age a second time.
func TestLifetime_IgnoresAgeForExpires(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)

	h := http.Header{
		"Expires": []string{now.Add(time.Hour).Format(http.TimeFormat)},
		"Age":     []string{"1800"},
	}

	if got, want := header.Lifetime(h, clock.Frozen(now)), time.Hour; got != want {
		t.Errorf("got %v; want %v", got, want)
	}
}

func TestAge(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want time.Duration
	}{
		{"absent", "", 0},
		{"zero", "0", 0},
		{"positive", "120", 2 * time.Minute},
		{"negative", "-120", 0},
		{"malformed", "two minutes", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := http.Header{}
			if tt.give != "" {
				h.Set("Age", tt.give)
			}

			if got := header.Age(h); got != tt.want {
				t.Errorf("got %v; want %v", got, tt.want)
			}
		})
	}
}
