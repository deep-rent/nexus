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

// Package throttle provides an in-memory, per-key token bucket for rate
// limiting.
//
// A [Throttle] hands out one token bucket per key and evicts the buckets that
// have gone idle, so memory tracks the number of active callers rather than
// growing without bound. Keys are opaque strings: a caller throttles by
// whatever identifies the actor, be it a network address, an account ID, or a
// one-time code. Namespacing distinct kinds of key (for example by prefixing
// them) is the caller's responsibility.
//
// # Primitives
//
// The core operations are keyed and free of any transport, so a [Throttle]
// can guard anything, not only HTTP:
//
//   - [Throttle.Allow] spends a token if one is available, reporting whether
//     the action may proceed. It is the ordinary rate-limit check.
//   - [Throttle.Blocked] peeks without spending and reports how long until a
//     token frees up, which is what a Retry-After header needs.
//   - [Throttle.Penalize] charges extra tokens after the fact, so that a
//     caller can make misbehavior — a failed login, an expensive query — cost
//     more than a well-behaved request.
//   - [Throttle.Reset] restores a key's full allowance.
//
// # HTTP
//
// For the common case of limiting HTTP requests by client address,
// [Throttle.Middleware] returns a ready-made [router.Middleware], and
// [RetryAfter] writes the corresponding header.
//
// # Usage
//
// Limit a route by client address in one line:
//
//	t := throttle.New(throttle.Config{})
//	r.Handle("POST /login", login, t.Middleware())
//
// Charge only the attempts that fail, so a caller who supplies valid
// credentials is never slowed down:
//
//	key := "user:" + username
//	if blocked, wait := t.Blocked(key); blocked {
//		throttle.RetryAfter(w.Header(), wait)
//		http.Error(w, "too many attempts", http.StatusTooManyRequests)
//		return
//	}
//	if !checkPassword(username, password) {
//		t.Penalize(key, 10) // A failure costs ten requests' worth.
//		return
//	}
//	t.Reset(key)
//
// # Scope
//
// Buckets are held in memory, so limits apply per process: a horizontally
// scaled deployment divides the effective allowance across replicas. This
// complements, but does not replace, volumetric rate limiting at the load
// balancer or reverse proxy.
package throttle
