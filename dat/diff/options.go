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

package diff

import (
	"github.com/deep-rent/nexus/dat/diff/hlc"
	"github.com/deep-rent/nexus/sys/log"
)

// Default engine limits.
const (
	// DefaultMaxChanges caps the number of changes accepted per request.
	DefaultMaxChanges = 500
	// DefaultMaxPatches caps the requestable patch feed page size.
	DefaultMaxPatches = 1000
	// DefaultLimit is the feed page size applied when the request omits one.
	DefaultLimit = 200
)

// config holds configuration options for the [Engine].
type config struct {
	logger     *log.Logger
	clock      *hlc.Clock
	prefilter  Prefilter
	maxChanges int
	maxLimit   int
	defLimit   int
}

// Option is a functional option for configuring the [Engine].
type Option func(*config)

// WithLogger sets the logger used for structured sync diagnostics.
// If not provided, logging is disabled. A nil logger is ignored.
func WithLogger(logger *log.Logger) Option {
	return func(c *config) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// WithClock injects the Hybrid Logical Clock instance, which is primarily
// useful for testing. A nil clock is ignored.
func WithClock(clock *hlc.Clock) Option {
	return func(c *config) {
		if clock != nil {
			c.clock = clock
		}
	}
}

// WithPrefilter installs an optional fast-path duplicate filter consulted
// before the transaction. A nil prefilter is ignored.
func WithPrefilter(p Prefilter) Option {
	return func(c *config) {
		if p != nil {
			c.prefilter = p
		}
	}
}

// WithMaxChanges overrides [DefaultMaxChanges]. Non-positive values are
// ignored.
func WithMaxChanges(n int) Option {
	return func(c *config) {
		if n > 0 {
			c.maxChanges = n
		}
	}
}

// WithMaxPatches overrides [DefaultMaxPatches]. Non-positive values are
// ignored.
func WithMaxPatches(n int) Option {
	return func(c *config) {
		if n > 0 {
			c.maxLimit = n
		}
	}
}

// WithDefaultLimit overrides [DefaultLimit]. Non-positive values are
// ignored.
func WithDefaultLimit(n int) Option {
	return func(c *config) {
		if n > 0 {
			c.defLimit = n
		}
	}
}
