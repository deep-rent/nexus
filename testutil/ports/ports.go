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

// Package ports provides network port management and synchronization functions,
// primarily designed for integration testing. It allows you to find free open
// ports and block execution until a specific port begins accepting connections.
//
// Note: Because this package imports the "testing" standard library, it should
// reside in a test-exclusive directory (e.g., internal/testutil/ports) to avoid
// compiling the testing framework into your final production binaries.
package ports

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

// Free asks the kernel for a free, open port that is ready to use.
func Free() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = l.Close()
	}()

	return l.Addr().(*net.TCPAddr).Port, nil
}

// FreeT is a test helper that wraps Free. It fails the test immediately if
// a free port cannot be found.
func FreeT(t testing.TB) int {
	t.Helper()
	port, err := Free()
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	return port
}

// Wait blocks until the specified host and port are accepting TCP connections,
// or until the context is canceled/times out.
func Wait(ctx context.Context, host string, port int) error {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	var d net.Dialer

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		// DialContext respects the context for the dial operation itself.
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return nil
		}

		select {
		case <-ctx.Done():
			// The context was canceled or its deadline exceeded.
			return ctx.Err()
		case <-ticker.C:
			// Wait for the next tick before trying again.
		}
	}
}

// WaitT is a test helper that wraps Wait. It fails the test immediately if
// the port does not become available before the context expires.
func WaitT(t testing.TB, ctx context.Context, host string, port int) {
	t.Helper()
	if err := Wait(ctx, host, port); err != nil {
		t.Fatalf("failed waiting for port %d on %s: %v", port, host, err)
	}
}
