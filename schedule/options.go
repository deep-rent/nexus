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

package schedule

import (
	"log/slog"
	"time"
)

// DefaultRecoveryDelay is the default duration to wait before running a [Tick]
// again after it panicked. It keeps a job that fails immediately on every run
// from spinning.
const DefaultRecoveryDelay = 1 * time.Minute

// config holds the internal settings for the scheduler.
type config struct {
	logger   *slog.Logger  // destination for internal logs
	recovery time.Duration // delay applied after a tick panicked
}

// Option is a function that configures the [Scheduler].
type Option func(*config)

// WithLogger provides a custom [slog.Logger] for the scheduler. It receives
// the report when a [Tick] panics. If not provided, [slog.Default] is used.
// A nil value is ignored.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// WithRecoveryDelay sets how long the scheduler waits before running a [Tick]
// again after it panicked. Without a delay, a tick that panics on every run
// would be retried in a tight loop.
//
// Values of zero or less are ignored, and [DefaultRecoveryDelay] is used
// instead.
func WithRecoveryDelay(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.recovery = d
		}
	}
}
