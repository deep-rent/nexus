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
// Define the desired [Options] and build an [http.Client]:
//
//	client := transport.NewClient(transport.Options{
//		Timeout:           10 * time.Second,
//		DisableKeepAlives: true,
//		ForceAttemptHTTP2: true,
//	})
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

// Options holds configuration for building an [http.Client] and its transport.
type Options struct {
	// Timeout sets the overall client timeout. Defaults to [DefaultTimeout]
	// if nonpositive.
	Timeout time.Duration
	// TLSConfig sets the TLS configuration for the transport.
	TLSConfig *tls.Config
	// DisableKeepAlives disables HTTP keep-alives.
	DisableKeepAlives bool
	// ForceAttemptHTTP2 enforces HTTP/2 support.
	ForceAttemptHTTP2 bool
	// Headers defines static headers applied to every request.
	Headers []header.Header
	// Retry configures the HTTP retry mechanism.
	Retry []retry.Option
}

// NewClient creates a new [*http.Client] configured with the provided options.
func NewClient(opts Options) *http.Client {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	d := &net.Dialer{
		Timeout: timeout / 3,
	}

	if opts.DisableKeepAlives {
		d.KeepAlive = -1
	}

	var t http.RoundTripper = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     opts.ForceAttemptHTTP2,
		TLSClientConfig:       opts.TLSConfig,
		TLSHandshakeTimeout:   timeout / 3,
		ResponseHeaderTimeout: timeout * 9 / 10,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		DisableKeepAlives:     opts.DisableKeepAlives,
	}

	// Add headers if any.
	if len(opts.Headers) > 0 {
		t = header.NewTransport(t, opts.Headers...)
	}

	// Enable retries if specified.
	if len(opts.Retry) > 0 {
		t = retry.NewTransport(t, opts.Retry...)
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: t,
	}
}
