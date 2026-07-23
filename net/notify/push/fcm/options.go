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
	"net/http"

	"github.com/deep-rent/nexus/std/clock"
	"github.com/deep-rent/nexus/sys/log"
)

const (
	// DefaultScope is the default scope for FCM v1 API.
	DefaultScope = "https://www.googleapis.com/auth/firebase.messaging"
	// DefaultBaseURL is the default base URL for FCM v1 API.
	DefaultBaseURL = "https://fcm.googleapis.com/v1"
	// DefaultAuthURL is the default authentication URL for FCM v1 API.
	DefaultAuthURL = "https://oauth2.googleapis.com/token"
)

type config struct {
	baseURL string
	authURL string
	logger  *log.Logger
	now     clock.Clock
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

// WithLogger injects a structured [log.Logger] into the sender. If not
// provided, the sender stays silent ([log.Discard]). Nil values are
// ignored.
func WithLogger(logger *log.Logger) Option {
	return func(cfg *config) {
		if logger != nil {
			cfg.logger = logger
		}
	}
}

// WithClock injects a custom clock function for JWT generation and caching.
// Nil values are ignored.
func WithClock(now clock.Clock) Option {
	return func(cfg *config) {
		if now != nil {
			cfg.now = now
		}
	}
}
