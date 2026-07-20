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

	"github.com/deep-rent/nexus/header"
)

// tripFunc adapts a function to the [http.RoundTripper] interface.
type tripFunc func(r *http.Request) (*http.Response, error)

func (f tripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// capture records the request seen by the wrapped transport.
func capture(seen **http.Request) tripFunc {
	return func(r *http.Request) (*http.Response, error) {
		*seen = r
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	}
}

// The transport must not observe later changes to the caller's slice.
func TestNewTransport_CopiesHeaders(t *testing.T) {
	t.Parallel()

	headers := []header.Header{header.New("X-Test", "original")}

	var seen *http.Request
	tr := header.NewTransport(capture(&seen), headers...)

	// Mutate the caller's slice after the transport was built.
	headers[0] = header.New("X-Test", "mutated")

	req, err := http.NewRequestWithContext(
		t.Context(), http.MethodGet, "http://example.com", nil,
	)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	if got, want := seen.Header.Get("X-Test"), "original"; got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestNewTransport_SetsHeaders(t *testing.T) {
	t.Parallel()

	var seen *http.Request
	tr := header.NewTransport(
		capture(&seen),
		header.New("X-One", "1"),
		header.UserAgent("nexus", "1.0", "https://deep.rent"),
	)

	req, err := http.NewRequestWithContext(
		t.Context(), http.MethodGet, "http://example.com", nil,
	)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	tests := []struct {
		key  string
		want string
	}{
		{"X-One", "1"},
		{"User-Agent", "nexus/1.0 (https://deep.rent)"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			if got := seen.Header.Get(tt.key); got != tt.want {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}
}

// The caller's request must be left untouched.
func TestNewTransport_ClonesRequest(t *testing.T) {
	t.Parallel()

	var seen *http.Request
	tr := header.NewTransport(capture(&seen), header.New("X-Test", "value"))

	req, err := http.NewRequestWithContext(
		t.Context(), http.MethodGet, "http://example.com", nil,
	)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}

	if got := req.Header.Get("X-Test"); got != "" {
		t.Errorf("caller's request was modified: got %q; want empty", got)
	}

	if seen == req {
		t.Error("request was not cloned")
	}
}

func TestNewTransport_NoHeaders(t *testing.T) {
	t.Parallel()

	var seen *http.Request
	base := capture(&seen)

	if got := header.NewTransport(base); got == nil {
		t.Error("got nil; want the base transport")
	}
}
