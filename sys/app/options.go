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

package app

import (
	"context"
	"os"
	"slices"
	"time"

	"github.com/deep-rent/nexus/sys/log"
)

// config holds the internal settings for the application runner, including
// logging, timeouts, signal handling, and parent context.
type config struct {
	logger  *log.Logger
	timeout time.Duration
	start   time.Duration
	signals []os.Signal
	ctx     context.Context
}

// Option is a function that configures the application runner [config].
type Option func(*config)

// WithLogger provides a custom [log.Logger] for the application runner. It is
// also made available to components via [Logger]. If not set, the runner
// defaults to a logger created by [log.New]. A nil value will be ignored.
func WithLogger(logger *log.Logger) Option {
	return func(c *config) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// WithTimeout sets the total duration granted to the shutdown process. If the
// components take longer than this to return, the runner gives up waiting and
// returns an error wrapping [ErrShutdownTimeout]. The same duration is
// reported to components by [ShutdownTimeout]. A negative or zero duration
// will be ignored, and [DefaultTimeout] is used instead.
//
// Note that the runner cannot forcibly terminate a component that ignores its
// context. On timeout it returns while those goroutines are still running,
// under the assumption that the caller exits the process shortly after.
func WithTimeout(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// WithStartTimeout sets the duration to wait for a [Stage] to signal readiness
// before the next stage is started. If the stage does not become ready in
// time, startup is aborted with an error wrapping [ErrStartTimeout]. A
// negative or zero duration will be ignored, and [DefaultStartTimeout] is used
// instead. This setting has no effect unless [RunStages] is used with more
// than one stage.
func WithStartTimeout(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.start = d
		}
	}
}

// WithSignals selects the [os.Signal] values that trigger a shutdown,
// replacing the default of [syscall.SIGTERM] and [syscall.SIGINT]. Passing no
// signals disables signal handling entirely, which is useful when the runner
// is embedded in a process that traps signals itself.
func WithSignals(signals ...os.Signal) Option {
	return func(c *config) {
		c.signals = slices.Clone(signals)
	}
}

// WithContext sets a parent [context.Context] for the runner. Cancelling it
// triggers a graceful shutdown. If not set, [context.Background] is used as
// the default parent. A nil value will be ignored.
//
// Because component contexts derive from this parent, cancelling it cancels
// every component at once. Ordered, reverse-stage shutdown as described in
// [RunStages] therefore only applies to shutdowns triggered by a signal or by
// a component.
func WithContext(ctx context.Context) Option {
	return func(c *config) {
		if ctx != nil {
			c.ctx = ctx
		}
	}
}
