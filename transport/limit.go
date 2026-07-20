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

package transport

import (
	"errors"
	"io"
	"net/http"
)

// DefaultMaxResponseBytes specifies the default limit on the size of a response
// body. It is deliberately generous; endpoints returning bulk payloads should
// raise it explicitly via [WithMaxResponseBytes].
const DefaultMaxResponseBytes = 1 << 20 // 1 MB

// ErrBodyTooLarge is returned by reads from a capped response body once the
// configured limit is exceeded.
//
// It is deliberately distinct from [io.EOF] so that a truncated payload can
// never be mistaken for a complete one: decoders that treat [io.EOF] as a
// clean end of input surface this error instead.
var ErrBodyTooLarge = errors.New("response body too large")

// Limit returns an [http.RoundTripper] that caps the size of every
// response body produced by next at max bytes.
//
// Reads up to and including the limit behave normally. A body that carries
// even one byte beyond the limit fails the read with [ErrBodyTooLarge] rather
// than reporting a short but seemingly complete body. Closing the capped body
// closes the underlying one.
//
// A nonpositive max disables the limit, in which case next is returned
// unchanged.
func Limit(next http.RoundTripper, max int64) http.RoundTripper {
	if max <= 0 {
		return next
	}
	return &limitTransport{next: next, max: max}
}

// limitTransport caps the response bodies returned by next.
type limitTransport struct {
	// next is the wrapped round tripper.
	next http.RoundTripper
	// max is the maximum number of body bytes to admit.
	max int64
}

// RoundTrip implements [http.RoundTripper].
func (t *limitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := t.next.RoundTrip(req)
	if err != nil || res == nil || res.Body == nil {
		return res, err
	}
	res.Body = &limitReader{
		body: res.Body,
		left: t.max,
	}
	return res, nil
}

var _ http.RoundTripper = (*limitTransport)(nil)

// limitReader wraps a response body and fails once more than left bytes have
// been read from it.
type limitReader struct {
	// body is the wrapped response body.
	body io.ReadCloser
	// left counts the bytes still admissible. It drops to -1 once the limit
	// has been exceeded.
	left int64
}

// Read implements [io.Reader]. It reads at most one byte beyond the remaining
// allowance in order to distinguish a body that ends exactly at the limit from
// one that overruns it.
func (r *limitReader) Read(p []byte) (int, error) {
	if r.left < 0 {
		return 0, ErrBodyTooLarge
	}
	if int64(len(p)) > r.left+1 {
		p = p[:r.left+1]
	}
	n, err := r.body.Read(p)
	if int64(n) <= r.left {
		r.left -= int64(n)
		return n, err
	}
	// The extra byte was consumed, so the body overruns the limit. Hand back
	// only the admissible prefix and fail this and every subsequent read.
	n = int(r.left)
	r.left = -1
	return n, ErrBodyTooLarge
}

// Close implements [io.Closer].
func (r *limitReader) Close() error { return r.body.Close() }

var _ io.ReadCloser = (*limitReader)(nil)
