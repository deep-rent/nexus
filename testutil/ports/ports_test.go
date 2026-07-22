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

package ports_test

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deep-rent/nexus/testutil/ports"
)

// fakeTB records failures instead of failing the enclosing test. It embeds
// [testing.TB] for interface compliance; only the overridden methods below
// may be called.
type fakeTB struct {
	testing.TB
	ctx context.Context

	mu    sync.Mutex
	fatal string
	dead  bool
}

func (f *fakeTB) Helper()                  {}
func (f *fakeTB) Logf(string, ...any)      {}
func (f *fakeTB) Context() context.Context { return f.ctx }

// Fatalf records the message and aborts the calling goroutine, mirroring the
// real implementation.
func (f *fakeTB) Fatalf(format string, args ...any) {
	f.mu.Lock()
	f.fatal = fmt.Sprintf(format, args...)
	f.dead = true
	f.mu.Unlock()
	runtime.Goexit()
}

// failure returns the recorded [fakeTB.Fatalf] message, if any.
func (f *fakeTB) failure() (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fatal, f.dead
}

// run invokes fn on a fresh goroutine and blocks until it returns or aborts
// via [runtime.Goexit], so that a [fakeTB] failure ends fn but not the test.
func run(fn func()) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	<-done
}

func TestFree(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		host string
	}{
		{"loopback", "127.0.0.1"},
		{"hostname", "localhost"},
		{"wildcard", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := ports.Free(t, tt.host)
			if p <= 0 || p > 65535 {
				t.Fatalf("got port %d; want in range (0, 65535]", p)
			}

			// The port must be immediately usable.
			addr := net.JoinHostPort(tt.host, strconv.Itoa(p))
			l, err := net.Listen("tcp", addr)
			if err != nil {
				t.Fatalf("when listening on %q: "+
					"should not have returned an error: %v", addr, err)
			}
			if err := l.Close(); err != nil {
				t.Errorf("should not have returned an error: %v", err)
			}
		})
	}
}

func TestFree_Error(t *testing.T) {
	t.Parallel()

	f := &fakeTB{ctx: t.Context()}
	run(func() { ports.Free(f, "500.0.0.1") })

	msg, dead := f.failure()
	if !dead {
		t.Fatal("should have failed the test")
	}
	if !strings.Contains(msg, "500.0.0.1") {
		t.Errorf("got failure %q; want mention of host", msg)
	}
}

func TestWait(t *testing.T) {
	t.Parallel()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	defer func() {
		_ = l.Close()
	}()

	p := l.Addr().(*net.TCPAddr).Port
	ports.Wait(t, "127.0.0.1", p)
}

func TestWait_Late(t *testing.T) {
	t.Parallel()

	p := ports.Free(t, "127.0.0.1")
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(p))

	// Start the listener only after a delay to exercise the polling loop.
	errc := make(chan error, 1)
	go func() {
		time.Sleep(300 * time.Millisecond)
		l, err := net.Listen("tcp", addr)
		if err != nil {
			errc <- err
			return
		}
		defer func() {
			_ = l.Close()
		}()
		errc <- nil
		<-t.Context().Done()
	}()

	ports.Wait(t, "127.0.0.1", p)
	if err := <-errc; err != nil {
		t.Fatalf("when listening on %q: "+
			"should not have returned an error: %v", addr, err)
	}
}

func TestWait_Timeout(t *testing.T) {
	t.Parallel()

	// No listener ever binds to the port.
	p := ports.Free(t, "127.0.0.1")

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()

	f := &fakeTB{ctx: ctx}
	run(func() { ports.Wait(f, "127.0.0.1", p) })

	msg, dead := f.failure()
	if !dead {
		t.Fatal("should have failed the test")
	}
	if !strings.Contains(msg, strconv.Itoa(p)) {
		t.Errorf("got failure %q; want mention of port %d", msg, p)
	}
}

func TestWait_Canceled(t *testing.T) {
	t.Parallel()

	p := ports.Free(t, "127.0.0.1")

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // Cancel up front.

	f := &fakeTB{ctx: ctx}
	run(func() { ports.Wait(f, "127.0.0.1", p) })

	if _, dead := f.failure(); !dead {
		t.Fatal("should have failed the test")
	}
}
