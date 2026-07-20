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

package retry

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
)

// Attempt encapsulates the state of a single HTTP request attempt.
//
// It is passed to a [Policy] to determine whether a retry is warranted. The
// response body, if any, must not be consumed by the policy: it is drained by
// the transport before the next attempt, and handed to the caller intact once
// the retry loop ends.
type Attempt struct {
	// Request is the request as it was sent for this attempt.
	Request *http.Request
	// Response is the result of the attempt, if one was received. It is nil
	// whenever Error is non-nil.
	Response *http.Response
	// Error is the error returned by the underlying transport, if any.
	Error error
	// Count is the number of the current attempt, starting at 1.
	Count int
}

// Idempotent reports whether the request can be safely retried.
//
// It considers the HTTP methods defined as idempotent by RFC 9110, namely GET,
// HEAD, OPTIONS, TRACE, PUT, and DELETE. Note that idempotency is a property
// of the server implementation; a POST endpoint guarded by an idempotency key
// is safe to retry even though this method reports otherwise.
func (a Attempt) Idempotent() bool {
	switch a.Request.Method {
	case
		http.MethodGet,
		http.MethodHead,
		http.MethodOptions,
		http.MethodTrace,
		http.MethodPut,
		http.MethodDelete:
		return true
	default:
		return false
	}
}

// Temporary reports whether the response indicates a server-side temporary
// failure.
//
// This is determined by specific HTTP status codes that suggest the request
// might succeed if retried, such as 408, 429, 500, 502, 503, and 504.
func (a Attempt) Temporary() bool {
	if a.Response == nil {
		return false
	}
	switch a.Response.StatusCode {
	case
		http.StatusRequestTimeout,      // 408
		http.StatusTooManyRequests,     // 429
		http.StatusInternalServerError, // 500
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable,  // 503
		http.StatusGatewayTimeout:      // 504
		return true
	default:
		return false
	}
}

// Transient reports whether the error suggests a temporary network-level
// issue.
//
// It returns true for network timeouts and for connections that were closed
// mid-flight. It returns false for context cancellations ([context.Canceled],
// [context.DeadlineExceeded]), since retrying cannot succeed once the caller
// has given up or its deadline has passed.
func (a Attempt) Transient() bool {
	if a.Error == nil ||
		errors.Is(a.Error, context.Canceled) ||
		errors.Is(a.Error, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(a.Error, io.ErrUnexpectedEOF) || errors.Is(a.Error, io.EOF) {
		return true
	}
	var err net.Error
	return errors.As(a.Error, &err) && err.Timeout()
}

// Policy is the decision-making function that determines whether to retry.
//
// It is invoked after each attempt with the corresponding [Attempt] details.
// It returns true to schedule a retry, or false to stop and return the last
// result to the caller. A policy is called from the goroutine driving the
// request and may be invoked concurrently for different requests, so it must
// not rely on shared mutable state.
type Policy func(a Attempt) bool

// LimitAttempts decorates a [Policy] to enforce a maximum attempt limit.
//
// It short-circuits the decision, returning false once the attempt count has
// reached the limit n. Otherwise, it delegates to the wrapped policy. A limit
// of 1 disables retries; a limit of 0 or less leaves the policy unchanged.
func (p Policy) LimitAttempts(n int) Policy {
	if n <= 0 {
		return p
	}
	return func(a Attempt) bool {
		return a.Count < n && p(a)
	}
}

// DefaultPolicy provides a safe and sensible default retry strategy.
//
// It retries only idempotent requests that resulted in a temporary server
// error or a transient network error such as a timeout. Requests that carry a
// body which cannot be rewound are never retried, regardless of the policy;
// see [NewTransport].
func DefaultPolicy() Policy {
	return func(a Attempt) bool {
		return a.Idempotent() && (a.Temporary() || a.Transient())
	}
}
