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

package oom

import (
	"math"
	"net/http"
	"runtime/debug"
	"runtime/metrics"
	"sync/atomic"
	"time"

	"github.com/deep-rent/nexus/router"
)

// ReasonOverload is returned when the server is rejecting requests due to
// resource exhaustion, such as approaching the memory limit.
const ReasonOverload = "server_overload"

// Middleware returns a [router.Middleware] that rejects new requests with a 503
// status when the application is about to run out of memory.
//
// It determines the limit from the active GOMEMLIMIT (via
// [debug.SetMemoryLimit]). If no limit is set, the middleware acts as a no-op.
// Otherwise, it starts a background goroutine to monitor memory usage and sheds
// load when the active heap size exceeds the configured threshold fraction.
func Middleware(opts ...Option) router.Middleware {
	limit := debug.SetMemoryLimit(-1)
	if limit <= 0 || limit == math.MaxInt64 {
		return func(next router.Handler) router.Handler { return next }
	}

	cfg := config{
		interval: DefaultInterval,
		fraction: DefaultThreshold,
		memory:   defaultMemoryProvider,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	threshold := uint64(float64(limit) * cfg.fraction)
	var lastCheck atomic.Int64
	var overloaded atomic.Bool

	return func(next router.Handler) router.Handler {
		return router.HandlerFunc(func(e *router.Exchange) error {
			now := time.Now().UnixNano()
			last := lastCheck.Load()

			if now-last > int64(cfg.interval) {
				if lastCheck.CompareAndSwap(last, now) {
					overloaded.Store(cfg.memory() >= threshold)
				}
			}

			if overloaded.Load() {
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
