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

// Package limit carries the throttling plumbing shared by the IAM server and
// the OAuth authorization server: the key namespaces that keep their bucket
// spaces disjoint, and the [Limiter] that charges, checks, and clears
// penalties against one shared throttle.
package limit

import (
	"net/http"

	"github.com/deep-rent/nexus/net/router"
	"github.com/deep-rent/nexus/net/throttle"
)

// Key namespaces keep the identifier spaces disjoint within the single
// [throttle.Throttle] shared across every axis the servers limit, so that a
// client ID can never share a bucket with a username, a one-time code, or a
// network address.
const (
	// ScopeAddr prefixes keys derived from the requesting network address.
	ScopeAddr = "addr:"
	// ScopeClient prefixes keys derived from OAuth client identifiers.
	ScopeClient = "client:"
	// ScopeUser prefixes keys derived from usernames.
	ScopeUser = "user:"
	// ScopeCode prefixes keys derived from device user codes.
	ScopeCode = "code:"
	// ScopeOTP prefixes keys derived from login flow handles.
	ScopeOTP = "otp:"
)

// Limiter charges failed authentication attempts against a shared throttle.
// The zero Limiter (nil throttle) disables every operation, so callers need
// no nil checks.
type Limiter struct {
	throttle *throttle.Throttle
	penalty  int
}

// New builds a [Limiter] over the given throttle, charging penalty tokens
// per failed attempt. A nil throttle disables limiting entirely.
func New(t *throttle.Throttle, penalty int) Limiter {
	return Limiter{throttle: t, penalty: penalty}
}

// Enabled reports whether a throttle is installed.
func (l Limiter) Enabled() bool { return l.throttle != nil }

// Throttled reports whether the given key has exhausted its throttle
// allowance, setting the Retry-After header when it has. It always reports
// false when throttling is disabled.
func (l Limiter) Throttled(e *router.Exchange, key string) bool {
	if l.throttle == nil {
		return false
	}
	blocked, wait := l.throttle.Blocked(key)
	if blocked {
		throttle.RetryAfter(e.W.Header(), wait)
	}
	return blocked
}

// Penalize charges a failed authentication attempt against the given keys.
func (l Limiter) Penalize(keys ...string) {
	if l.throttle == nil {
		return
	}
	for _, key := range keys {
		l.throttle.Penalize(key, l.penalty)
	}
}

// Clear restores the throttle allowance of a credential that has just been
// proven. Address-scoped keys are deliberately never cleared, so that
// holding one valid credential cannot wipe the penalty accrued while
// guessing others.
func (l Limiter) Clear(key string) {
	if l.throttle != nil {
		l.throttle.Reset(key)
	}
}

// Addr returns the address-scoped throttle key for the request, or an empty
// string when throttling is disabled. It matches the key [Limiter.Middleware]
// spends against, so that per-request volume and per-attempt penalties draw
// down one shared bucket.
func (l Limiter) Addr(e *router.Exchange) string {
	if l.throttle == nil {
		return ""
	}
	return ScopeAddr + throttle.RemoteAddr(e.R)
}

// Middleware spends one token per request from the requesting address's
// bucket, rejecting the request with 429 once the bucket is empty. It must
// only be installed when [Limiter.Enabled] reports true.
func (l Limiter) Middleware() router.Middleware {
	return l.throttle.MiddlewareFunc(func(r *http.Request) string {
		return ScopeAddr + throttle.RemoteAddr(r)
	})
}
