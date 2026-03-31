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

// Package check provides a collection of standard health check constructors
// for common infrastructure dependencies like TCP, HTTP, DNS, and Databases.
//
// These functions return a health.CheckFunc that can be registered with a
// health.Monitor.
//
// Example:
//
//	monitor := health.NewMonitor()
//
//	// Check a Redis instance via TCP
//	monitor.Register(
//		"redis",
//		2*time.Second,
//		check.TCP("localhost:6379", 1*time.Second),
//	)
//
//	// Check an external API with a custom HTTP client
//	monitor.Register(
//		"stripe",
//		10*time.Second,
//		check.HTTP(client, "https://api.stripe.com/health"),
//	)
package check

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/deep-rent/nexus/health"
)

// TCP returns a health check that attempts to establish a TCP connection
// to the specified address. It returns health.StatusSick if the connection
// cannot be established within the provided timeout.
func TCP(addr string, timeout time.Duration) health.CheckFunc {
	return func(ctx context.Context) (health.Status, error) {
		d := net.Dialer{Timeout: timeout}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return health.StatusSick, fmt.Errorf("tcp dial %s: %w", addr, err)
		}
		_ = conn.Close()
		return health.StatusHealthy, nil
	}
}

// HTTP returns a health check that performs a GET request to the specified URL.
// If client is nil, http.DefaultClient is employed.
//
// The check logic includes:
//  1. Fallback Timeout: If neither the client nor the request context has a
//     deadline, a 10-second timeout is applied.
//  2. Connection Hygiene: The response body is fully drained and closed
//     to ensure the underlying TCP connection can be reused.
//  3. Status Codes: Any status code in the 2xx or 3xx range is considered healthy.
func HTTP(client *http.Client, url string) health.CheckFunc {
	const defaultTimeout = 10 * time.Second

	if client == nil {
		client = http.DefaultClient
	}

	return func(ctx context.Context) (health.Status, error) {
		child := ctx

		// If the client has no timeout set, we enforce a fallback timeout
		// specifically for this check execution using the context.
		// We only do this if the incoming context doesn't already have a deadline.
		if _, deadline := ctx.Deadline(); !deadline && client.Timeout == 0 {
			var cancel context.CancelFunc
			child, cancel = context.WithTimeout(ctx, defaultTimeout)
			defer cancel()
		}

		req, err := http.NewRequestWithContext(child, http.MethodGet, url, nil)
		if err != nil {
			return health.StatusSick, fmt.Errorf("http: request %s: %w", url, err)
		}

		res, err := client.Do(req)
		if err != nil {
			return health.StatusSick, fmt.Errorf("http: get %s: %w", url, err)
		}

		// Ensure the body is drained so the connection can be reused.
		defer func() {
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
		}()

		code := res.StatusCode
		if code >= http.StatusOK && code < http.StatusBadRequest {
			return health.StatusHealthy, nil
		}

		return health.StatusSick, fmt.Errorf(
			"http: get %s: unexpected status code: %d",
			url, code,
		)
	}
}

// Pinger is an interface for types that support context-aware connectivity
// checks. This is most commonly satisfied by *sql.DB from the standard library.
type Pinger interface {
	// PingContext verifies a connection to the target system is still alive.
	PingContext(ctx context.Context) error
}

// Ping returns a health check that calls PingContext on the provided Pinger.
// It is ideal for monitoring the health of SQL database connections.
func Ping(p Pinger) health.CheckFunc {
	return func(ctx context.Context) (health.Status, error) {
		if err := p.PingContext(ctx); err != nil {
			return health.StatusSick, err
		}
		return health.StatusHealthy, nil
	}
}

// DNS returns a health check that verifies the provided host resolves
// to at least one IP address using the default system resolver.
func DNS(host string) health.CheckFunc {
	return func(ctx context.Context) (health.Status, error) {
		_, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil {
			return health.StatusSick, fmt.Errorf("dns lookup %s: %w", host, err)
		}
		return health.StatusHealthy, nil
	}
}

// Wrap converts a simple function that returns an error into a health check
// callback. The resulting check is not context-aware and will ignore the
// context passed during execution.
func Wrap(fn func() error) health.CheckFunc {
	return func(ctx context.Context) (health.Status, error) {
		if err := fn(); err != nil {
			return health.StatusSick, err
		}
		return health.StatusHealthy, nil
	}
}

// WrapContext converts a context-aware function into a health check callback.
// This is used for custom checks that need to respect timeouts or
// cancellation signals.
func WrapContext(fn func(context.Context) error) health.CheckFunc {
	return func(ctx context.Context) (health.Status, error) {
		if err := fn(ctx); err != nil {
			return health.StatusSick, err
		}
		return health.StatusHealthy, nil
	}
}
