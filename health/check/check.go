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

package check

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/deep-rent/nexus/health"
)

// TCP tests connectivity to a given address.
func TCP(addr string, timeout time.Duration) health.CheckFunc {
	return func(ctx context.Context) (health.Status, error) {
		d := net.Dialer{Timeout: timeout}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return health.StatusSick, err
		}
		conn.Close()
		return health.StatusHealthy, nil
	}
}

// HTTP performs a GET request to the specified URL.
func HTTP(url string, timeout time.Duration) health.CheckFunc {
	client := &http.Client{Timeout: timeout}
	return func(ctx context.Context) (health.Status, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return health.StatusSick, err
		}
		res, err := client.Do(req)
		if err != nil {
			return health.StatusSick, err
		}
		defer func() {
			_ = res.Body.Close()
		}()

		if res.StatusCode >= 200 && res.StatusCode < 400 {
			return health.StatusHealthy, nil
		}
		err = fmt.Errorf("unexpected status code: %d", res.StatusCode)
		return health.StatusSick, err
	}
}

// Pinger is an interface for types that support context-aware pinging,
// like *sql.DB.
type Pinger interface {
	PingContext(ctx context.Context) error
}

// Ping executes a PingContext on the provided interface.
func Ping(p Pinger) health.CheckFunc {
	return func(ctx context.Context) (health.Status, error) {
		if err := p.PingContext(ctx); err != nil {
			return health.StatusSick, err
		}
		return health.StatusHealthy, nil
	}
}

// DNS verifies that the given host resolves to at least one IP address.
func DNS(host string) health.CheckFunc {
	return func(ctx context.Context) (health.Status, error) {
		_, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil {
			return health.StatusSick, fmt.Errorf("dns lookup %s: %w", host, err)
		}
		return health.StatusHealthy, nil
	}
}
