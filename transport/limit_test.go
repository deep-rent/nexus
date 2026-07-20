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

package transport_test

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/deep-rent/nexus/transport"
)

// stubTripper returns a canned response carrying the given body.
type stubTripper struct {
	body string
	// bodyless makes the stub return a response without a body.
	bodyless bool
	// closed records whether the response body was closed.
	closed bool
}

func (s *stubTripper) RoundTrip(*http.Request) (*http.Response, error) {
	res := &http.Response{StatusCode: http.StatusOK}
	if !s.bodyless {
		res.Body = &closeTracker{
			Reader: strings.NewReader(s.body),
			closed: &s.closed,
		}
	}
	return res, nil
}

// closeTracker records whether Close was called.
type closeTracker struct {
	io.Reader
	closed *bool
}

func (c *closeTracker) Close() error {
	*c.closed = true
	return nil
}

// roundTrip sends a request through rt and returns the response.
func roundTrip(t *testing.T, rt http.RoundTripper) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	res, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip failed: %v", err)
	}
	return res
}

func TestLimit_UnderLimit(t *testing.T) {
	const body = "hello"
	rt := transport.Limit(&stubTripper{body: body}, 1024)

	res := roundTrip(t, rt)
	got, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if string(got) != body {
		t.Errorf("body: got %q; want %q", got, body)
	}
}

func TestLimit_AtLimit(t *testing.T) {
	const body = "hello"
	rt := transport.Limit(
		&stubTripper{body: body},
		int64(len(body)),
	)

	res := roundTrip(t, rt)
	got, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("a body ending exactly at the limit must not fail: %v", err)
	}
	if string(got) != body {
		t.Errorf("body: got %q; want %q", got, body)
	}
}

func TestLimit_OverLimit(t *testing.T) {
	const body = "hello world"
	rt := transport.Limit(&stubTripper{body: body}, 5)

	res := roundTrip(t, rt)
	got, err := io.ReadAll(res.Body)

	if !errors.Is(err, transport.ErrBodyTooLarge) {
		t.Fatalf("error: got %v; want %v", err, transport.ErrBodyTooLarge)
	}
	// The error must not be mistakable for a clean end of input.
	if errors.Is(err, io.EOF) {
		t.Error("overflow must not be reported as io.EOF")
	}
	// Only the admissible prefix may be handed back.
	if want := body[:5]; string(got) != want {
		t.Errorf("body: got %q; want %q", got, want)
	}
}

func TestLimit_OverLimitIsSticky(t *testing.T) {
	rt := transport.Limit(&stubTripper{body: "hello world"}, 5)

	res := roundTrip(t, rt)
	if _, err := io.ReadAll(res.Body); !errors.Is(
		err, transport.ErrBodyTooLarge,
	) {
		t.Fatalf("error: got %v; want %v", err, transport.ErrBodyTooLarge)
	}

	// Every subsequent read must keep failing rather than resuming.
	buf := make([]byte, 8)
	for i := range 3 {
		n, err := res.Body.Read(buf)
		if !errors.Is(err, transport.ErrBodyTooLarge) {
			t.Errorf(
				"read %d: error got %v; want %v",
				i, err, transport.ErrBodyTooLarge,
			)
		}
		if n != 0 {
			t.Errorf("read %d: got %d bytes; want 0", i, n)
		}
	}
}

func TestLimit_SmallReads(t *testing.T) {
	// Reading through a buffer smaller than the limit must accumulate the
	// bytes consumed rather than resetting the allowance per call.
	rt := transport.Limit(&stubTripper{body: "abcdefghij"}, 4)

	res := roundTrip(t, rt)

	buf := make([]byte, 2)
	var got []byte
	var err error
	for err == nil {
		var n int
		n, err = res.Body.Read(buf)
		got = append(got, buf[:n]...)
	}

	if !errors.Is(err, transport.ErrBodyTooLarge) {
		t.Fatalf("error: got %v; want %v", err, transport.ErrBodyTooLarge)
	}
	if want := "abcd"; string(got) != want {
		t.Errorf("body: got %q; want %q", got, want)
	}
}

func TestLimit_Disabled(t *testing.T) {
	next := &stubTripper{body: "hello"}
	for _, max := range []int64{0, -1} {
		if rt := transport.Limit(next, max); rt != next {
			t.Errorf("max %d: expected next to be returned unwrapped", max)
		}
	}
}

func TestLimit_NilBody(t *testing.T) {
	rt := transport.Limit(&stubTripper{bodyless: true}, 8)

	res := roundTrip(t, rt)
	if res.Body != nil {
		t.Error("expected a nil body to be left alone")
	}
}

func TestLimit_Close(t *testing.T) {
	next := &stubTripper{body: "hello"}
	rt := transport.Limit(next, 8)

	res := roundTrip(t, rt)
	if err := res.Body.Close(); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if !next.closed {
		t.Error("expected the underlying body to be closed")
	}
}

func TestNew_LimitsResponseBodyByDefault(t *testing.T) {
	// Consumers rely on bodies being capped without opting in, so the limiter
	// must be part of the default stack.
	rt := transport.New()
	next, max, ok := transport.Unwrap(rt)
	if !ok {
		t.Fatalf("expected transport to be limited, got %T", rt)
	}
	if exp := int64(transport.DefaultMaxResponseBytes); exp != max {
		t.Errorf("max: got %d; want %d", max, exp)
	}

	// The limiter must sit innermost so that the intermediate responses seen
	// by the retry transport are capped too.
	if _, ok := next.(*http.Transport); !ok {
		t.Errorf("expected limiter to wrap *http.Transport, got %T", next)
	}
}

func TestNew_MaxResponseBytes(t *testing.T) {
	_, max, ok := transport.Unwrap(transport.New(
		transport.WithMaxResponseBytes(64),
	))
	if !ok {
		t.Fatal("expected transport to be limited")
	}
	if exp := int64(64); exp != max {
		t.Errorf("max: got %d; want %d", max, exp)
	}

	// A nonpositive limit disables capping entirely.
	if _, _, ok := transport.Unwrap(transport.New(
		transport.WithMaxResponseBytes(0),
	)); ok {
		t.Error("expected a zero limit to disable capping")
	}
}

func TestDefaultClient_LimitsResponseBody(t *testing.T) {
	_, max, ok := transport.Unwrap(transport.DefaultClient.Transport)
	if !ok {
		t.Fatalf(
			"expected DefaultClient to cap bodies, got %T",
			transport.DefaultClient.Transport,
		)
	}
	if exp := int64(transport.DefaultMaxResponseBytes); exp != max {
		t.Errorf("max: got %d; want %d", max, exp)
	}
}
