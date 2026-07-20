package transport

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// stubTripper returns a canned response carrying the given body.
type stubTripper struct {
	body string
	nil  bool // return a response without a body
}

func (s *stubTripper) RoundTrip(*http.Request) (*http.Response, error) {
	res := &http.Response{StatusCode: http.StatusOK}
	if !s.nil {
		res.Body = io.NopCloser(strings.NewReader(s.body))
	}
	return res, nil
}

// roundTrip sends a request through rt and returns the response body.
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

func TestNewLimitTransport_UnderLimit(t *testing.T) {
	const body = "hello"
	rt := NewLimitTransport(&stubTripper{body: body}, 1024)

	res := roundTrip(t, rt)
	got, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if string(got) != body {
		t.Errorf("body: got %q; want %q", got, body)
	}
}

func TestNewLimitTransport_AtLimit(t *testing.T) {
	const body = "hello"
	rt := NewLimitTransport(&stubTripper{body: body}, int64(len(body)))

	res := roundTrip(t, rt)
	got, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("a body ending exactly at the limit must not fail: %v", err)
	}
	if string(got) != body {
		t.Errorf("body: got %q; want %q", got, body)
	}
}

func TestNewLimitTransport_OverLimit(t *testing.T) {
	const body = "hello world"
	rt := NewLimitTransport(&stubTripper{body: body}, 5)

	res := roundTrip(t, rt)
	got, err := io.ReadAll(res.Body)

	if !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("error: got %v; want %v", err, ErrBodyTooLarge)
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

func TestNewLimitTransport_OverLimitIsSticky(t *testing.T) {
	rt := NewLimitTransport(&stubTripper{body: "hello world"}, 5)

	res := roundTrip(t, rt)
	if _, err := io.ReadAll(res.Body); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("error: got %v; want %v", err, ErrBodyTooLarge)
	}

	// Every subsequent read must keep failing rather than resuming.
	buf := make([]byte, 8)
	for i := range 3 {
		n, err := res.Body.Read(buf)
		if !errors.Is(err, ErrBodyTooLarge) {
			t.Errorf("read %d: error got %v; want %v", i, err, ErrBodyTooLarge)
		}
		if n != 0 {
			t.Errorf("read %d: got %d bytes; want 0", i, n)
		}
	}
}

func TestNewLimitTransport_SmallReads(t *testing.T) {
	// Reading through a buffer smaller than the limit must accumulate the
	// bytes consumed rather than resetting the allowance per call.
	rt := NewLimitTransport(&stubTripper{body: "abcdefghij"}, 4)

	res := roundTrip(t, rt)

	buf := make([]byte, 2)
	var got []byte
	var err error
	for err == nil {
		var n int
		n, err = res.Body.Read(buf)
		got = append(got, buf[:n]...)
	}

	if !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("error: got %v; want %v", err, ErrBodyTooLarge)
	}
	if want := "abcd"; string(got) != want {
		t.Errorf("body: got %q; want %q", got, want)
	}
}

func TestNewLimitTransport_Disabled(t *testing.T) {
	next := &stubTripper{body: "hello"}
	for _, max := range []int64{0, -1} {
		if rt := NewLimitTransport(next, max); rt != next {
			t.Errorf("max %d: expected next to be returned unwrapped", max)
		}
	}
}

func TestNewLimitTransport_NilBody(t *testing.T) {
	rt := NewLimitTransport(&stubTripper{nil: true}, 8)

	res := roundTrip(t, rt)
	if res.Body != nil {
		t.Error("expected a nil body to be left alone")
	}
}

func TestNewLimitTransport_Close(t *testing.T) {
	var closed bool
	body := &closeTracker{
		Reader: strings.NewReader("hello"),
		closed: &closed,
	}
	lb := &limitBody{body: body, left: 8}

	if err := lb.Close(); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	if !closed {
		t.Error("expected the underlying body to be closed")
	}
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

func TestNew_LimitsResponseBodyByDefault(t *testing.T) {
	// Consumers rely on bodies being capped without opting in, so the limiter
	// must be part of the default stack.
	lt, ok := New().(*limitTransport)
	if !ok {
		t.Fatalf("expected transport to be *limitTransport, got %T", New())
	}
	if exp, act := int64(DefaultMaxResponseBytes), lt.max; exp != act {
		t.Errorf("max: got %d; want %d", act, exp)
	}

	// The limiter must sit innermost so that the intermediate responses seen
	// by the retry transport are capped too.
	if _, ok := lt.next.(*http.Transport); !ok {
		t.Errorf("expected limiter to wrap *http.Transport, got %T", lt.next)
	}
}

func TestNew_MaxResponseBytes(t *testing.T) {
	lt, ok := New(WithMaxResponseBytes(64)).(*limitTransport)
	if !ok {
		t.Fatal("expected transport to be *limitTransport")
	}
	if exp, act := int64(64), lt.max; exp != act {
		t.Errorf("max: got %d; want %d", act, exp)
	}

	// A nonpositive limit disables capping entirely.
	if _, ok := New(WithMaxResponseBytes(0)).(*limitTransport); ok {
		t.Error("expected a zero limit to disable capping")
	}
}

func TestDefaultClient_LimitsResponseBody(t *testing.T) {
	lt, ok := DefaultClient.Transport.(*limitTransport)
	if !ok {
		t.Fatalf(
			"expected DefaultClient to cap bodies, got %T",
			DefaultClient.Transport,
		)
	}
	if exp, act := int64(DefaultMaxResponseBytes), lt.max; exp != act {
		t.Errorf("max: got %d; want %d", act, exp)
	}
}
