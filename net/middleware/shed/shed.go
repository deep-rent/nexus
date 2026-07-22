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

package shed

import (
	"math"
	"net/http"
	"runtime/debug"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/deep-rent/nexus/net/router"
)

// ReasonOverload is returned when the server is rejecting requests due to
// resource exhaustion, such as approaching the memory limit.
const ReasonOverload = "server_overload"

// New returns a [router.Middleware] that rejects new requests with a 503
// status when the application is about to run out of memory.
//
// It determines the limit from the active GOMEMLIMIT (via
// [debug.SetMemoryLimit]). If no limit is set, it returns nil, which
// [router.Chain] skips entirely. Otherwise, it monitors memory usage inline and
// sheds load when the active heap size exceeds the configured threshold
// fraction.
func New(opts ...Option) router.Middleware {
	limit := debug.SetMemoryLimit(-1)
	if limit <= 0 || limit == math.MaxInt64 {
		// No memory limit set: return nil so middleware chaining skips
		// it entirely.
		return nil
	}

	cfg := config{
		interval:   DefaultInterval,
		fraction:   DefaultThreshold,
		retryAfter: DefaultRetryAfter,
		memory:     memory,
		now:        time.Now,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	threshold := uint64(float64(limit) * cfg.fraction)
	var overloaded atomic.Bool
	var last atomic.Int64 // unix nanos of the most recent sample

	after := strconv.Itoa(int(math.Ceil(cfg.retryAfter.Seconds())))

	return func(next router.Handler) router.Handler {
		return router.HandlerFunc(func(e *router.Exchange) error {
			// Sample at most once per interval. The CAS operation claims the
			// sampling slot for exactly one goroutine; concurrent requests read
			// the last recorded verdict from overloaded.
			curr, prev := cfg.now(), last.Load()
			if curr.Sub(time.Unix(0, prev)) > cfg.interval &&
				last.CompareAndSwap(prev, curr.UnixNano()) {
				overloaded.Store(cfg.memory() >= threshold)
			}

			if overloaded.Load() {
				e.W.Header().Set("Retry-After", after)
				return router.Fail(
					http.StatusServiceUnavailable,
					ReasonOverload,
					"the server is currently overloaded; try again later",
				)
			}
			return next.ServeHTTP(e)
		})
	}
}
