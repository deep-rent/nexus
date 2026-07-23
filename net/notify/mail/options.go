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

package mail

import (
	"log/slog"
	"net/http"
)

// config holds the optional configuration for the [sender].
type config struct {
	// baseURL overrides the default SendGrid API endpoint.
	baseURL string
	// userAgent defines the User-Agent header value for outgoing requests.
	userAgent string
	// logger specifies the custom structured [slog.Logger].
	logger *slog.Logger
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

// WithBaseURL allows overriding the SendGrid API base URL for testing or
// mocking. Empty string values are ignored, since an empty base URL would
// leave the sender pointed at a relative path that fails at send time.
func WithBaseURL(url string) Option {
	return func(c *config) {
		if url != "" {
			c.baseURL = url
		}
	}
}

// WithUserAgent configures a custom User-Agent header for the outbound
// API requests.
func WithUserAgent(v string) Option {
	return func(c *config) {
		c.userAgent = v
	}
}

// WithLogger injects a structured [slog.Logger] into the sender.
// Nil values will be ignored.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) {
		if logger != nil {
			c.logger = logger
		}
	}
}
