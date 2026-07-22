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

package ports

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

const (
	// timeout caps how long [Wait] polls before failing the test. It guards
	// against tests hanging until the test binary times out when a server
	// never comes up and the test context carries no earlier deadline.
	timeout = 10 * time.Second
	// interval is the delay between successive dial attempts in [Wait].
	interval = 100 * time.Millisecond
)

// Free asks the kernel for a TCP port that is free on the given host and
// returns its number. An empty host allocates a port that is free on all
// interfaces. If no port can be allocated, the test fails immediately.
//
// The temporary listener backing the allocation is closed before Free
// returns; see the package documentation for the implications.
func Free(t testing.TB, host string) int {
	t.Helper()

	l, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatalf("failed to allocate free port on %q: %v", host, err)
	}

	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("failed to cast address of type %T", l.Addr())
	}
	if err := l.Close(); err != nil {
		t.Logf("failed to release port %d on %q: %v", addr.Port, host, err)
	}

	return addr.Port
}

// Wait blocks until a TCP server accepts connections on the given host and
// port.
//
// It dials the address every 100ms until a connection succeeds. If the test
// context is canceled or its deadline is exceeded first, or no dial succeeds
// within 30 seconds, the test fails immediately.
func Wait(t testing.TB, host string, port int) {
	t.Helper()

	addr := net.JoinHostPort(host, strconv.Itoa(port))

	// Bound the polling even if the test context has no earlier deadline.
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var d net.Dialer
	for {
		// Respect the context for the dial operation itself.
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			if err := conn.Close(); err != nil {
				t.Logf("failed to close connection to %s: %v", addr, err)
			}
			return
		}

		select {
		case <-ctx.Done():
			// The context was canceled or its deadline exceeded.
			t.Fatalf("failed waiting for port %d on %q: %v", port, host, err)
		case <-ticker.C:
			// Wait for the next tick before trying again.
		}
	}
}
