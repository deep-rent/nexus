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

package apns

import (
	"net/http"

	"github.com/deep-rent/nexus/std/clock"
	"github.com/deep-rent/nexus/sys/log"
)

const (
	// DefaultBaseURL is the production endpoint for APNs.
	DefaultBaseURL = "https://api.push.apple.com"
	// SandboxBaseURL is the sandbox endpoint for APNs.
	SandboxBaseURL = "https://api.sandbox.push.apple.com"
)

type config struct {
	baseURL string
	topic   string
	logger  *log.Logger
	now     clock.Clock
	client  *http.Client
}

// Option defines the functional option pattern for configuring the APNs sender.
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

// WithBaseURL allows overriding the APNs API base URL.
// Useful for switching to [SandboxBaseURL] or mocking.
// Empty string values are ignored.
func WithBaseURL(url string) Option {
	return func(cfg *config) {
		if url != "" {
			cfg.baseURL = url
		}
	}
}

// WithTopic sets the default apns-topic header, which is the app's bundle
// identifier (optionally with a type suffix such as ".voip"). APNs requires it
// for most push types, so it is normally configured once here rather than per
// message. A message may still override it via [push.Target.Topic]. Empty
// string values are ignored.
func WithTopic(topic string) Option {
	return func(cfg *config) {
		if topic != "" {
			cfg.topic = topic
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
