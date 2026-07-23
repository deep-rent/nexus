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

package scrape

import (
	"net/http"
	"time"

	"github.com/deep-rent/nexus/sys/log"
)

// DefaultTimeout bounds a single target fetch unless the context imposes a
// tighter deadline.
const DefaultTimeout = 10 * time.Second

// config holds the collector settings.
type config struct {
	client  *http.Client
	logger  *log.Logger
	timeout time.Duration
}

// Option configures a [Collector].
type Option func(*config)

// WithClient sets the HTTP client used to fetch snapshots. It defaults to a
// client built by [transport.NewClient] with the default timeout. A nil
// value is ignored.
func WithClient(client *http.Client) Option {
	return func(c *config) {
		if client != nil {
			c.client = client
		}
	}
}

// WithLogger sets the logger receiving scrape failures. If not provided,
// the collector stays silent, as if [log.Discard] had been given. A nil
// value is ignored.
func WithLogger(logger *log.Logger) Option {
	return func(c *config) {
		if logger != nil {
			c.logger = logger
		}
	}
}

// WithTimeout bounds each target fetch. Values of zero or less are ignored,
// keeping [DefaultTimeout].
func WithTimeout(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.timeout = d
		}
	}
}
