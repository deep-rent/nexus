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

package transport

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/deep-rent/nexus/net/header"
	"github.com/deep-rent/nexus/net/retry"
	"github.com/deep-rent/nexus/sys/metrics"
)

// DefaultTimeout specifies the default overall timeout for HTTP clients.
const DefaultTimeout = 5 * time.Second

// DefaultDialTimeout is the maximum amount of time a dial will wait for
// a connect to complete.
const DefaultDialTimeout = 2 * time.Second

// DefaultKeepAlive specifies the interval between keep-alive probes for an
// active network connection.
const DefaultKeepAlive = 30 * time.Second

// DefaultTLSHandshakeTimeout specifies the maximum amount of time waiting to
// wait for a TLS handshake.
const DefaultTLSHandshakeTimeout = 2 * time.Second

// DefaultMaxIdleConns specifies the maximum number of idle (keep-alive)
// connections across all hosts.
const DefaultMaxIdleConns = 1024

// DefaultMaxIdleConnsPerHost specifies the maximum number of idle (keep-alive)
// connections per host.
const DefaultMaxIdleConnsPerHost = 1024

// DefaultIdleConnTimeout specifies the maximum amount of time an idle
// (keep-alive) connection will remain idle before closing itself.
const DefaultIdleConnTimeout = 90 * time.Second

// DefaultExpectContinueTimeout specifies the amount of time to wait for
// a server's first response headers after fully writing the request headers if
// the request has an "Expect: 100-continue" header.
const DefaultExpectContinueTimeout = 1 * time.Second

// DefaultForceAttemptHTTP2 specifies whether to attempt HTTP/2 by default.
const DefaultForceAttemptHTTP2 = true

// DefaultMaxConnsPerHost optionally limits the total number of connections per
// host.
const DefaultMaxConnsPerHost = 1024

// DefaultResponseHeaderTimeout specifies the amount of time to wait for a
// server's response headers.
const DefaultResponseHeaderTimeout = 0

// DefaultMaxResponseHeaderBytes specifies a limit on how many response bytes
// are allowed in the server's response header.
const DefaultMaxResponseHeaderBytes = 64 * 1024 // 64 KB

// DefaultWriteBufferSize specifies the size of the write buffer used.
const DefaultWriteBufferSize = 4 * 1024 // 4 KB

// DefaultReadBufferSize specifies the size of the read buffer used.
const DefaultReadBufferSize = 4 * 1024 // 4 KB

// config is used to hold the configuration for a [Transport].
type config struct {
	dialTimeout            time.Duration
	keepAlive              time.Duration
	tlsHandshakeTimeout    time.Duration
	expectContinueTimeout  time.Duration
	idleConnTimeout        time.Duration
	tlsConfig              *tls.Config
	disableKeepAlives      bool
	forceAttemptHTTP2      bool
	disableCompression     bool
	headers                []header.Header
	retry                  []retry.Option
	metrics                bool
	metricsOpts            []MetricsOption
	maxIdleConns           int
	maxIdleConnsPerHost    int
	maxConnsPerHost        int
	responseHeaderTimeout  time.Duration
	maxResponseHeaderBytes int64
	maxResponseBytes       int64
	writeBufferSize        int
	readBufferSize         int
	http2Config            *http.HTTP2Config
	protocols              *http.Protocols
	proxy                  Proxy
	dialer                 Dialer
}

// Option configures an [http.Transport] via [New].
type Option func(*config)

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
// the request has an "Expect: 100-continue" header. Defaults to
// [DefaultExpectContinueTimeout].
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
	return func(c *config) {
		if cfg != nil {
			c.tlsConfig = cfg.Clone()
		}
	}
}

// WithDisableKeepAlives disables HTTP keep-alives.
func WithDisableKeepAlives(disabled bool) Option {
	return func(c *config) { c.disableKeepAlives = disabled }
}

// WithForceAttemptHTTP2 enforces HTTP/2 support.
func WithForceAttemptHTTP2(force bool) Option {
	return func(c *config) { c.forceAttemptHTTP2 = force }
}

// WithDisableCompression prevents the Transport from requesting compression.
func WithDisableCompression(disable bool) Option {
	return func(c *config) { c.disableCompression = disable }
}

// WithResponseHeaderTimeout specifies the amount of time to wait for a server's
// response headers.
func WithResponseHeaderTimeout(d time.Duration) Option {
	return func(c *config) {
		if d >= 0 {
			c.responseHeaderTimeout = d
		}
	}
}

// WithMaxResponseHeaderBytes specifies a limit on how many response bytes are
// allowed in the server's response header.
func WithMaxResponseHeaderBytes(max int64) Option {
	return func(c *config) {
		if max >= 0 {
			c.maxResponseHeaderBytes = max
		}
	}
}

// WithMaxResponseBytes caps the size of response bodies. Reading a body beyond
// the limit fails with [ErrBodyTooLarge]. Defaults to
// [DefaultMaxResponseBytes]. Nonpositive values disable the limit.
func WithMaxResponseBytes(max int64) Option {
	return func(c *config) { c.maxResponseBytes = max }
}

// WithWriteBufferSize specifies the size of the write buffer used.
func WithWriteBufferSize(size int) Option {
	return func(c *config) {
		if size >= 0 {
			c.writeBufferSize = size
		}
	}
}

// WithReadBufferSize specifies the size of the read buffer used.
func WithReadBufferSize(size int) Option {
	return func(c *config) {
		if size >= 0 {
			c.readBufferSize = size
		}
	}
}

// WithHTTP2Config configures HTTP/2 connections.
func WithHTTP2Config(cfg *http.HTTP2Config) Option {
	return func(c *config) { c.http2Config = cfg }
}

// WithProtocols specifies the set of protocols supported by the transport.
func WithProtocols(protocols *http.Protocols) Option {
	return func(c *config) { c.protocols = protocols }
}

// WithProxy defines a custom proxy function. Pass http.ProxyURL(nil) to disable
// proxying.
func WithProxy(proxy Proxy) Option {
	return func(c *config) { c.proxy = proxy }
}

// WithDialContext overrides the default net.Dialer.
func WithDialContext(dialer Dialer) Option {
	return func(c *config) { c.dialer = dialer }
}

// WithHeader defines static headers applied to every request.
func WithHeader(h ...header.Header) Option {
	return func(c *config) { c.headers = append(c.headers, h...) }
}

// WithUserAgent defines the User-Agent header applied to every request.
func WithUserAgent(v string) Option {
	return WithHeader(header.New("User-Agent", v))
}

// WithRetry configures the HTTP retry mechanism.
func WithRetry(opts ...retry.Option) Option {
	return func(c *config) { c.retry = append(c.retry, opts...) }
}

// WithMetrics enables client request measurement; see [NewMetricsTransport]
// for what is recorded.
//
// The measuring layer sits below the retry and header layers, so every
// retry attempt is captured as its own observation.
func WithMetrics(opts ...MetricsOption) Option {
	return func(c *config) {
		c.metrics = true
		c.metricsOpts = append(c.metricsOpts, opts...)
	}
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

// WithMaxConnsPerHost optionally limits the total number of connections per
// host.
// Negative values are ignored.
func WithMaxConnsPerHost(max int) Option {
	return func(c *config) {
		if max >= 0 {
			c.maxConnsPerHost = max
		}
	}
}

// metricsConfig holds the configuration for a metrics transport.
type metricsConfig struct {
	registry *metrics.Registry
}

// MetricsOption configures a metrics transport created by
// [NewMetricsTransport] or enabled via [WithMetrics].
type MetricsOption func(*metricsConfig)

// WithRegistry sets the destination registry. It defaults to
// [metrics.DefaultRegistry]. A nil value is ignored.
func WithRegistry(reg *metrics.Registry) MetricsOption {
	return func(c *metricsConfig) {
		if reg != nil {
			c.registry = reg
		}
	}
}
