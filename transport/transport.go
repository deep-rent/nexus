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
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/deep-rent/nexus/header"
	"github.com/deep-rent/nexus/retry"
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

// Proxy defines a custom proxy function.
type Proxy func(*http.Request) (*url.URL, error)

// Dialer defines a custom dial function for creating network connections.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

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
	trace                  bool
	traceOpts              []TraceOption
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

// WithTrace enables OpenTelemetry client instrumentation; see
// [NewTraceTransport] for what is recorded.
//
// The tracing layer sits below the retry and header layers, so every retry
// attempt is captured as its own client span carrying the final headers of
// the request.
func WithTrace(opts ...TraceOption) Option {
	return func(c *config) {
		c.trace = true
		c.traceOpts = append(c.traceOpts, opts...)
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

// New creates a new [http.RoundTripper] configured with the provided options.
func New(opts ...Option) http.RoundTripper {
	cfg := config{
		dialTimeout:            DefaultDialTimeout,
		keepAlive:              DefaultKeepAlive,
		tlsHandshakeTimeout:    DefaultTLSHandshakeTimeout,
		expectContinueTimeout:  DefaultExpectContinueTimeout,
		idleConnTimeout:        DefaultIdleConnTimeout,
		maxIdleConns:           DefaultMaxIdleConns,
		maxIdleConnsPerHost:    DefaultMaxIdleConnsPerHost,
		forceAttemptHTTP2:      DefaultForceAttemptHTTP2,
		maxConnsPerHost:        DefaultMaxConnsPerHost,
		responseHeaderTimeout:  DefaultResponseHeaderTimeout,
		maxResponseHeaderBytes: DefaultMaxResponseHeaderBytes,
		maxResponseBytes:       DefaultMaxResponseBytes,
		writeBufferSize:        DefaultWriteBufferSize,
		readBufferSize:         DefaultReadBufferSize,
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

	proxy := http.ProxyFromEnvironment
	if cfg.proxy != nil {
		proxy = cfg.proxy
	}

	dialContext := d.DialContext
	if cfg.dialer != nil {
		dialContext = cfg.dialer
	}

	var t http.RoundTripper = &http.Transport{
		Proxy:                  proxy,
		DialContext:            dialContext,
		ForceAttemptHTTP2:      cfg.forceAttemptHTTP2,
		TLSClientConfig:        cfg.tlsConfig,
		TLSHandshakeTimeout:    cfg.tlsHandshakeTimeout,
		ExpectContinueTimeout:  cfg.expectContinueTimeout,
		MaxIdleConns:           cfg.maxIdleConns,
		MaxIdleConnsPerHost:    cfg.maxIdleConnsPerHost,
		MaxConnsPerHost:        cfg.maxConnsPerHost,
		IdleConnTimeout:        cfg.idleConnTimeout,
		DisableKeepAlives:      cfg.disableKeepAlives,
		DisableCompression:     cfg.disableCompression,
		ResponseHeaderTimeout:  cfg.responseHeaderTimeout,
		MaxResponseHeaderBytes: cfg.maxResponseHeaderBytes,
		WriteBufferSize:        cfg.writeBufferSize,
		ReadBufferSize:         cfg.readBufferSize,
		HTTP2:                  cfg.http2Config,
		Protocols:              cfg.protocols,
	}

	// Cap response bodies first so that the limit also applies to the
	// intermediate responses observed by the retry transport.
	t = Limit(t, cfg.maxResponseBytes)

	// The tracing layer sits below retry and header, so that each attempt is
	// recorded as its own span carrying the final request headers.
	if cfg.trace {
		t = NewTraceTransport(t, cfg.traceOpts...)
	}

	// Add headers if any.
	if len(cfg.headers) > 0 {
		t = header.NewTransport(t, cfg.headers...)
	}

	// Enable retries if specified.
	if len(cfg.retry) > 0 {
		t = retry.NewTransport(t, cfg.retry...)
	}

	return t
}

// NewClient creates a new HTTP client configured with the given overall timeout
// and sensible defaults that can be tuned with the provided options. If the
// specified timeout is nonpositive, the [DefaultTimeout] will be applied
// instead.
func NewClient(timeout time.Duration, opts ...Option) *http.Client {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: New(opts...),
	}
}

// DefaultClient is the client used by packages in this module when the caller
// does not supply one of their own. Unlike [http.DefaultClient] it carries the
// connection hygiene established by [NewClient], most importantly an overall
// [DefaultTimeout] and a [DefaultMaxResponseBytes] cap on response bodies.
//
// Consumers that read response bodies may therefore rely on those bodies being
// bounded without applying their own [io.LimitReader]. Callers who pass a
// custom client are responsible for that guarantee themselves; building it
// with [NewClient] preserves it.
//
// It is shared, so its connection pool is shared too. Do not mutate it; pass a
// client built by [NewClient] instead.
var DefaultClient = NewClient(0)
