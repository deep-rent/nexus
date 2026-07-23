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

package flush

import "time"

// Default configuration values for a new [Writer].
const (
	// DefaultSize is the buffer capacity used when none is specified.
	DefaultSize = 64 << 10
	// DefaultInterval is the flush interval used when none is specified.
	// It bounds the loss window on a crash to one second of output.
	DefaultInterval = time.Second
)

// config holds the configuration settings for a [Writer].
type config struct {
	// size is the buffer capacity in bytes.
	size int
	// interval is the cadence of background flushes.
	interval time.Duration
}

// Option defines a function that modifies the [Writer] configuration.
type Option func(*config)

// WithSize sets the buffer capacity in bytes. A full buffer is flushed
// inline by the write that fills it. Sizes less than one are ignored.
func WithSize(n int) Option {
	return func(c *config) {
		if n > 0 {
			c.size = n
		}
	}
}

// WithInterval sets the cadence of background flushes, bounding both the
// staleness of observable output and the loss window on a crash. A
// nonpositive interval disables background flushing entirely, leaving
// only capacity, [Writer.Flush], and [Writer.Close] to trigger writes.
func WithInterval(d time.Duration) Option {
	return func(c *config) {
		c.interval = d
	}
}
