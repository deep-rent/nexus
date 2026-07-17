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

// Package transport provides an abstraction for building robust HTTP clients.
//
// It centralizes the configuration of HTTP timeouts, connection pools, and
// middleware like retry logic and static headers, ensuring standard
// connection hygiene across all API consumers.
//
// # Usage
//
// Define the desired options and build an [http.Client]:
//
//	client := transport.NewClient(
//		transport.WithTimeout(10 * time.Second),
//		transport.WithDisableKeepAlives(true),
//		transport.WithForceAttemptHTTP2(true),
//	)
package transport

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/deep-rent/nexus/header"
	"github.com/deep-rent/nexus/retry"
)

// DefaultTimeout specifies the default overall timeout for HTTP clients.
const DefaultTimeout = 5 * time.Second

type config struct {
	timeout             time.Duration
	tlsConfig           *tls.Config
	disableKeepAlives   bool
	forceAttemptHTTP2   bool
	headers             []header.Header
	retry               []retry.Option
	maxIdleConns        int
	maxIdleConnsPerHost int
}

// Option configures an [http.Client] via [NewClient].
type Option func(*config)

// WithTimeout sets the overall client timeout. Defaults to [DefaultTimeout]
// if nonpositive or unspecified.
func WithTimeout(d time.Duration) Option {
	return func(c *config) { c.timeout = d }
}

// WithTLSConfig sets the TLS configuration for the transport.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(c *config) { c.tlsConfig = cfg }
}

// WithDisableKeepAlives disables HTTP keep-alives.
func WithDisableKeepAlives(disabled bool) Option {
	return func(c *config) { c.disableKeepAlives = disabled }
}

// WithForceAttemptHTTP2 enforces HTTP/2 support.
func WithForceAttemptHTTP2(force bool) Option {
	return func(c *config) { c.forceAttemptHTTP2 = force }
}

// WithHeader defines static headers applied to every request.
func WithHeader(h ...header.Header) Option {
	return func(c *config) { c.headers = append(c.headers, h...) }
}

// WithRetry configures the HTTP retry mechanism.
func WithRetry(opts ...retry.Option) Option {
	return func(c *config) { c.retry = append(c.retry, opts...) }
}

// WithMaxIdleConns configures the maximum number of idle (keep-alive)
// connections across all hosts. Defaults to 100.
func WithMaxIdleConns(max int) Option {
	return func(c *config) { c.maxIdleConns = max }
}

// WithMaxIdleConnsPerHost configures the maximum number of idle (keep-alive)
// connections per host. Defaults to 100.
func WithMaxIdleConnsPerHost(max int) Option {
	return func(c *config) { c.maxIdleConnsPerHost = max }
}

// NewClient creates a new [*http.Client] configured with the provided options.
func NewClient(opts ...Option) *http.Client {
	cfg := config{
		timeout:             DefaultTimeout,
		maxIdleConns:        100,
		maxIdleConnsPerHost: 100,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	timeout := cfg.timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	d := &net.Dialer{
		Timeout: timeout / 3,
	}

	if cfg.disableKeepAlives {
		d.KeepAlive = -1
	}

	var t http.RoundTripper = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     cfg.forceAttemptHTTP2,
		TLSClientConfig:       cfg.tlsConfig,
		TLSHandshakeTimeout:   timeout / 3,
		ResponseHeaderTimeout: timeout * 9 / 10,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConns:          cfg.maxIdleConns,
		MaxIdleConnsPerHost:   cfg.maxIdleConnsPerHost,
		IdleConnTimeout:       90 * time.Second,
		DisableKeepAlives:     cfg.disableKeepAlives,
	}

	// Add headers if any.
	if len(cfg.headers) > 0 {
		t = header.NewTransport(t, cfg.headers...)
	}

	// Enable retries if specified.
	if len(cfg.retry) > 0 {
		t = retry.NewTransport(t, cfg.retry...)
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: t,
	}
}
