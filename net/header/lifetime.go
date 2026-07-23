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

package header

import (
	"net/http"
	"strconv"
	"time"

	"github.com/deep-rent/nexus/std/clock"
)

// Lifetime determines the cache lifetime of a response based on caching
// headers. It reads the current time from the given clock to calculate
// relative times. It returns a duration of 0 if the response is not cacheable
// or does not carry any caching information.
//
// Directives are evaluated as a set rather than in the order they appear, so
// a no-store or no-cache anywhere in Cache-Control suppresses the lifetime
// even when a max-age precedes it. A no-cache that names specific fields
// (no-cache="Set-Cookie") only marks those fields for revalidation and leaves
// the lifetime intact.
//
// The time a response has already spent in upstream caches, as reported by
// the Age header, is subtracted from a max-age. No such correction applies to
// Expires, which names an absolute instant and is therefore measured against
// the clock directly.
func Lifetime(h http.Header, now clock.Clock) time.Duration {
	// Cache-Control takes precedence over Expires
	if v := h.Get("Cache-Control"); v != "" {
		var (
			maxAge time.Duration
			found  bool
		)

		for k, v := range Directives(v) {
			switch k {
			case "no-store":
				return 0
			case "no-cache":
				// Only the unqualified form forbids reuse outright.
				if v == "" {
					return 0
				}
			case "max-age":
				if d, err := strconv.ParseInt(v, 10, 64); err == nil {
					// A negative age denotes a response that is already
					// stale, not one that expired in the past.
					maxAge, found = max(0, time.Duration(d)*time.Second), true
				}
			}
		}

		if found {
			// What remains of the age budget after the time the response
			// already spent being relayed.
			return max(0, maxAge-Age(h))
		}
	}
	if v := h.Get("Expires"); v != "" {
		if t, err := http.ParseTime(v); err == nil {
			if d := t.Sub(now()); d > 0 {
				return d
			}
		}
	}
	return 0
}

// Age reports how long a response has been held in caches on its way to the
// client, as stated by the Age header. It returns 0 if the header is absent,
// malformed, or negative.
func Age(h http.Header) time.Duration {
	v := h.Get("Age")
	if v == "" {
		return 0
	}
	d, err := strconv.ParseInt(v, 10, 64)
	if err != nil || d < 0 {
		return 0
	}
	return time.Duration(d) * time.Second
}
