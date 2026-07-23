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

package fcm

import (
	"log/slog"
	"net/http"
	"time"
)

type config struct {
	baseURL string
	authURL string
	logger  *slog.Logger
	now     func() time.Time
	client  *http.Client
}

// Option defines the functional option pattern for configuring the FCM sender.
type Option func(*config)

// WithClient sets the [http.Client] used for outbound API requests. Defaults
// to [transport.DefaultClient]. Nil values are ignored.
func WithClient(client *http.Client) Option {
	return func(cfg *config) {
		if client != nil {
			cfg.client = client
		}
	}
}

// WithBaseURL allows overriding the FCM API base URL.
// Useful for mocking. Empty string values are ignored.
func WithBaseURL(url string) Option {
	return func(cfg *config) {
		if url != "" {
			cfg.baseURL = url
		}
	}
}

// WithAuthURL allows overriding the Google OAuth 2.0 token endpoint.
// Useful for mocking. Empty string values are ignored.
func WithAuthURL(url string) Option {
	return func(cfg *config) {
		if url != "" {
			cfg.authURL = url
		}
	}
}

// WithLogger injects a structured [slog.Logger] into the sender.
// Nil values are ignored.
func WithLogger(logger *slog.Logger) Option {
	return func(cfg *config) {
		if logger != nil {
			cfg.logger = logger
		}
	}
}

// WithClock injects a custom clock function for JWT generation and caching.
// Nil values are ignored.
func WithClock(now func() time.Time) Option {
	return func(cfg *config) {
		if now != nil {
			cfg.now = now
		}
	}
}
