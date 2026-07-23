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

package text

import (
	"net/http"

	"github.com/deep-rent/nexus/sys/log"
)

const (
	// DefaultBaseURL is the standard API endpoint for Twilio Messaging.
	DefaultBaseURL = "https://api.twilio.com/2010-04-01"
)

// config holds the optional configuration for the [sender].
type config struct {
	// baseURL overrides the default Twilio API endpoint.
	baseURL string
	// logger specifies the custom structured [log.Logger].
	logger *log.Logger
	// client is the HTTP client used for outbound API requests.
	client *http.Client
}

// Option defines the functional option pattern for configuring the [sender].
type Option func(*config)

// WithClient sets the [http.Client] used for outbound API requests. Defaults
// to [transport.DefaultClient]. Nil values are ignored.
func WithClient(client *http.Client) Option {
	return func(c *config) {
		if client != nil {
			c.client = client
		}
	}
}

// WithBaseURL allows overriding the Twilio API base URL for testing or mocking.
// Empty string values are ignored.
func WithBaseURL(url string) Option {
	return func(c *config) {
		if url != "" {
			c.baseURL = url
		}
	}
}

// WithLogger injects a structured [log.Logger] into the sender. If not
// provided, the sender stays silent ([log.Discard]). Nil values are
// ignored.
func WithLogger(logger *log.Logger) Option {
	return func(c *config) {
		if logger != nil {
			c.logger = logger
		}
	}
}
