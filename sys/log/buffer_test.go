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

package log_test

import (
	"bytes"
	"strings"
	"sync"
	"testing"

	"github.com/deep-rent/nexus/sys/log"
)

func TestBuffer_Empty(t *testing.T) {
	t.Parallel()

	var b log.Buffer
	if got := b.String(); got != "" {
		t.Errorf("got %q; want empty", got)
	}
	if got := b.Lines(); len(got) != 0 {
		t.Errorf("got %d lines; want 0", len(got))
	}
}

func TestBuffer_Lines(t *testing.T) {
	t.Parallel()

	var b log.Buffer
	if _, err := b.Write([]byte("one\ntwo\n")); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	lines := b.Lines()
	if got, want := len(lines), 2; got != want {
		t.Fatalf("got %d lines; want %d", got, want)
	}
	if lines[0] != "one" || lines[1] != "two" {
		t.Errorf("got %q; want [one two]", lines)
	}
}

func TestBuffer_Reset(t *testing.T) {
	t.Parallel()

	var b log.Buffer
	if _, err := b.Write([]byte("data\n")); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	b.Reset()
	if got := b.String(); got != "" {
		t.Errorf("got %q after reset; want empty", got)
	}
}

func TestBuffer_Bytes_Copy(t *testing.T) {
	t.Parallel()

	var b log.Buffer
	if _, err := b.Write([]byte("abc")); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Mutating the returned slice must not affect the buffer.
	p := b.Bytes()
	p[0] = 'x'
	if got, want := b.String(), "abc"; got != want {
		t.Errorf("got %q; want %q", got, want)
	}
	if !bytes.Equal(b.Bytes(), []byte("abc")) {
		t.Error("buffer content changed through the copy")
	}
}

// The buffer must tolerate reads while writes are still in flight; the
// race detector verifies the locking.
func TestBuffer_Concurrent(t *testing.T) {
	t.Parallel()

	var b log.Buffer
	var wg sync.WaitGroup

	for range 4 {
		wg.Go(func() {
			for range 100 {
				_, _ = b.Write([]byte("line\n"))
				_ = b.String()
				_ = b.Lines()
			}
		})
	}
	wg.Wait()

	if got, want := len(b.Lines()), 400; got != want {
		t.Errorf("got %d lines; want %d", got, want)
	}
}

func TestCapture_OverridesWriter(t *testing.T) {
	t.Parallel()

	// The returned buffer must win over a writer set through options.
	var other log.Buffer
	logger, buf := log.Capture(log.WithWriter(&other))
	logger.Info(t.Context(), "m")

	if other.String() != "" {
		t.Errorf("output leaked to the overridden writer: %q", other.String())
	}
	if !strings.Contains(buf.String(), `"msg":"m"`) {
		t.Errorf("output missing from the buffer: %q", buf.String())
	}
}
