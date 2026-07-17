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

// DefaultDialTimeout is the maximum amount of time a dial will wait for
// a connect to complete.
const DefaultDialTimeout = 30 * time.Second

// DefaultKeepAlive specifies the interval between keep-alive probes for an
// active network connection.
const DefaultKeepAlive = 30 * time.Second

// DefaultTLSHandshakeTimeout specifies the maximum amount of time waiting to
// wait for a TLS handshake.
const DefaultTLSHandshakeTimeout = 10 * time.Second

// DefaultMaxIdleConns specifies the maximum number of idle (keep-alive)
// connections across all hosts.
const DefaultMaxIdleConns = 100

// DefaultMaxIdleConnsPerHost specifies the maximum number of idle (keep-alive)
// connections per host.
const DefaultMaxIdleConnsPerHost = 100

// DefaultIdleConnTimeout specifies the maximum amount of time an idle
// (keep-alive) connection will remain idle before closing itself.
const DefaultIdleConnTimeout = 90 * time.Second

// DefaultExpectContinueTimeout specifies the amount of time to wait for
// a server's first response headers after fully writing the request headers if
// the request has an "Expect: 100-continue" header.
const DefaultExpectContinueTimeout = 1 * time.Second

type config struct {
	timeout               time.Duration
	dialTimeout           time.Duration
	keepAlive             time.Duration
	tlsHandshakeTimeout   time.Duration
	expectContinueTimeout time.Duration
	idleConnTimeout       time.Duration
	tlsConfig             *tls.Config
	disableKeepAlives     bool
	forceAttemptHTTP2     bool
	headers               []header.Header
	retry                 []retry.Option
	maxIdleConns          int
	maxIdleConnsPerHost   int
}

// Option configures an [http.Client] via [NewClient].
type Option func(*config)

// WithTimeout sets the overall client timeout. Defaults to [DefaultTimeout]
// if unspecified. A timeout of zero means no timeout. Negative values are
// ignored.
func WithTimeout(d time.Duration) Option {
	return func(c *config) {
		if d >= 0 {
			c.timeout = d
		}
	}
}

// WithDialTimeout specifies the maximum amount of time a dial will wait for
// a connect to complete. Defaults to [DefaultDialTimeout].
// Negative values are ignored.
func WithDialTimeout(d time.Duration) Option {
	return func(c *config) {
		if d >= 0 {
			c.dialTimeout = d
		}
	}
}

// WithKeepAlive specifies the interval between keep-alive probes for an
// active network connection. Defaults to [DefaultKeepAlive].
// Negative values are ignored.
func WithKeepAlive(d time.Duration) Option {
	return func(c *config) {
		if d >= 0 {
			c.keepAlive = d
		}
	}
}

// WithTLSHandshakeTimeout specifies the maximum amount of time waiting to
// wait for a TLS handshake. Defaults to [DefaultTLSHandshakeTimeout].
// Negative values are ignored.
func WithTLSHandshakeTimeout(d time.Duration) Option {
	return func(c *config) {
		if d >= 0 {
			c.tlsHandshakeTimeout = d
		}
	}
}

// WithExpectContinueTimeout specifies the amount of time to wait for
// a server's first response headers after fully writing the request headers if
// the request has an "Expect: 100-continue" header. Defaults to [DefaultExpectContinueTimeout].
// Negative values are ignored.
func WithExpectContinueTimeout(d time.Duration) Option {
	return func(c *config) {
		if d >= 0 {
			c.expectContinueTimeout = d
		}
	}
}

// WithIdleConnTimeout specifies the maximum amount of time an idle
// (keep-alive) connection will remain idle before closing itself.
// Defaults to [DefaultIdleConnTimeout]. Negative values are ignored.
func WithIdleConnTimeout(d time.Duration) Option {
	return func(c *config) {
		if d >= 0 {
			c.idleConnTimeout = d
		}
	}
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
// connections across all hosts. Defaults to [DefaultMaxIdleConns].
// Negative values are ignored.
func WithMaxIdleConns(max int) Option {
	return func(c *config) {
		if max >= 0 {
			c.maxIdleConns = max
		}
	}
}

// WithMaxIdleConnsPerHost configures the maximum number of idle (keep-alive)
// connections per host. Defaults to [DefaultMaxIdleConnsPerHost].
// Negative values are ignored.
func WithMaxIdleConnsPerHost(max int) Option {
	return func(c *config) {
		if max >= 0 {
			c.maxIdleConnsPerHost = max
		}
	}
}

// NewClient creates a new [*http.Client] configured with the provided options.
func NewClient(opts ...Option) *http.Client {
	cfg := config{
		timeout:               DefaultTimeout,
		dialTimeout:           DefaultDialTimeout,
		keepAlive:             DefaultKeepAlive,
		tlsHandshakeTimeout:   DefaultTLSHandshakeTimeout,
		expectContinueTimeout: DefaultExpectContinueTimeout,
		idleConnTimeout:       DefaultIdleConnTimeout,
		maxIdleConns:          DefaultMaxIdleConns,
		maxIdleConnsPerHost:   DefaultMaxIdleConnsPerHost,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	d := &net.Dialer{
		Timeout:   cfg.dialTimeout,
		KeepAlive: cfg.keepAlive,
	}

	if cfg.disableKeepAlives {
		d.KeepAlive = -1
	}

	var t http.RoundTripper = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     cfg.forceAttemptHTTP2,
		TLSClientConfig:       cfg.tlsConfig,
		TLSHandshakeTimeout:   cfg.tlsHandshakeTimeout,
		ExpectContinueTimeout: cfg.expectContinueTimeout,
		MaxIdleConns:          cfg.maxIdleConns,
		MaxIdleConnsPerHost:   cfg.maxIdleConnsPerHost,
		IdleConnTimeout:       cfg.idleConnTimeout,
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
		Timeout:   cfg.timeout,
		Transport: t,
	}
}
