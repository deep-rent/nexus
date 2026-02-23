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
	"fmt"
	"net"
	"testing"
	"time"
)

// Free asks the kernel for a free, open port that is ready to use.
func Free() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
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
// or until the timeout duration is reached. It returns true if successful.
func Wait(host string, port int, timeout time.Duration) bool {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	end := time.Now().Add(timeout)

	for time.Now().Before(end) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}
