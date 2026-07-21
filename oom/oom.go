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

const (
	// pollInterval is the frequency at which the background goroutine checks
	// the application's memory usage.
	pollInterval = 250 * time.Millisecond

	// thresholdFraction is the fraction of GOMEMLIMIT at which the server will
	// begin rejecting requests to avoid an OOM kill.
	thresholdFraction = 0.90
)

// Middleware returns a [router.Middleware] that rejects new requests with a 503
// status when the application is about to run out of memory.
//
// It determines the limit from the active GOMEMLIMIT (via
// [debug.SetMemoryLimit]). If no limit is set, the middleware acts as a no-op.
// Otherwise, it starts a background goroutine to monitor memory usage and sheds
// load when the active heap size exceeds 90% of the configured limit.
func Middleware() router.Middleware {
	limit := debug.SetMemoryLimit(-1)
	if limit <= 0 || limit == math.MaxInt64 {
		return func(next router.Handler) router.Handler { return next }
	}

	threshold := uint64(float64(limit) * thresholdFraction)
	var overloaded atomic.Bool

	go func() {
		ticker := time.NewTicker(pollInterval)
		defer ticker.Stop()

		samples := []metrics.Sample{
			{Name: "/memory/classes/total:bytes"},
			{Name: "/memory/classes/heap/released:bytes"},
		}

		for range ticker.C {
			metrics.Read(samples)
			total := samples[0].Value.Uint64()
			released := samples[1].Value.Uint64()

			// The memory charged against GOMEMLIMIT is the total mapped
			// memory minus the memory returned to the OS.
			inUse := uint64(0)
			if total > released {
				inUse = total - released
			}

			overloaded.Store(inUse >= threshold)
		}
	}()

	return func(next router.Handler) router.Handler {
		return router.HandlerFunc(func(e *router.Exchange) error {
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
