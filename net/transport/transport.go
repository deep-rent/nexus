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
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/deep-rent/nexus/net/header"
	"github.com/deep-rent/nexus/net/retry"
)

// Proxy defines a custom proxy function.
type Proxy func(*http.Request) (*url.URL, error)

// Dialer defines a custom dial function for creating network connections.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

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

	// The measuring layer sits below retry and header, so that each attempt
	// is recorded as its own observation.
	if cfg.metrics {
		t = NewMetricsTransport(t, cfg.metricsOpts...)
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
