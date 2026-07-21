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
	"runtime/metrics"
	"time"
)

type config struct {
	interval time.Duration
	fraction float64
	memory   func() uint64
}

// Option configures the OOM middleware.
type Option func(*config)

const (
	// DefaultInterval is the frequency at which the middleware checks memory
	// usage.
	DefaultInterval = 250 * time.Millisecond

	// DefaultThreshold is the fraction of GOMEMLIMIT at which the server begins
	// rejecting requests.
	DefaultThreshold = 0.90
)

// WithInterval sets the frequency at which the middleware checks memory usage.
// Defaults to [DefaultInterval].
func WithInterval(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.interval = d
		}
	}
}

// WithThreshold sets the fraction of GOMEMLIMIT at which the server begins
// rejecting requests. Defaults to [DefaultThreshold].
func WithThreshold(fraction float64) Option {
	return func(c *config) {
		if fraction > 0 && fraction <= 1.0 {
			c.fraction = fraction
		}
	}
}

// WithMemoryProvider overrides the function used to query the current memory in
// use. It is primarily useful for testing. Defaults to reading the runtime
// metrics.
func WithMemoryProvider(provider func() uint64) Option {
	return func(c *config) {
		if provider != nil {
			c.memory = provider
		}
	}
}

func defaultMemoryProvider() uint64 {
	samples := []metrics.Sample{
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
	}
	metrics.Read(samples)
	total := samples[0].Value.Uint64()
	released := samples[1].Value.Uint64()

	if total > released {
		return total - released
	}
	return 0
}
