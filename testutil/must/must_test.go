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

package must_test

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"

	"github.com/deep-rent/nexus/testutil/must"
)

// fakeTB records failures instead of failing the enclosing test. It embeds
// [testing.TB] for interface compliance; only the overridden methods below
// may be called.
type fakeTB struct {
	testing.TB

	mu    sync.Mutex
	fatal string
	dead  bool
}

func (f *fakeTB) Helper() {}

// Fatal records the message and aborts the calling goroutine, mirroring the
// real implementation.
func (f *fakeTB) Fatal(args ...any) {
	f.mu.Lock()
	f.fatal = fmt.Sprint(args...)
	f.dead = true
	f.mu.Unlock()
	runtime.Goexit()
}

// failure returns the recorded [fakeTB.Fatal] message, if any.
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

func TestPanic(t *testing.T) {
	t.Parallel()

	errBoom := errors.New("boom")

	tests := []struct {
		name string
		give any
	}{
		{"string", "boom"},
		{"error", errBoom},
		{"int", 42},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := must.Panic(t, func() { panic(tt.give) })
			if r != tt.give {
				t.Errorf("got %v; want %v", r, tt.give)
			}
		})
	}
}

func TestPanic_None(t *testing.T) {
	t.Parallel()

	f := &fakeTB{}
	run(func() { must.Panic(f, func() {}) })

	msg, dead := f.failure()
	if !dead {
		t.Fatal("should have failed the test")
	}
	if want := "should have panicked"; msg != want {
		t.Errorf("got failure %q; want %q", msg, want)
	}
}
