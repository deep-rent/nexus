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

package flush_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deep-rent/nexus/std/flush"
)

// fakeWriter records writes and can be inspected concurrently. It counts
// the number of underlying writes so tests can observe batching.
type fakeWriter struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	writes int
	err    error
}

func (f *fakeWriter) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, f.err
	}
	f.writes++
	return f.buf.Write(p)
}

func (f *fakeWriter) String() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.buf.String()
}

func (f *fakeWriter) Writes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes
}

// eventually polls the specified function until it either reports true or the
// deadline expires.
func eventually(t *testing.T, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not reached in time")
}

func TestWriter_Buffers(t *testing.T) {
	t.Parallel()

	dst := new(fakeWriter)
	w := flush.New(dst, flush.WithInterval(0))
	defer w.Close()

	if _, err := w.Write([]byte("one\n")); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if _, err := w.Write([]byte("two\n")); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Small writes must not reach the destination before a flush.
	if got := dst.Writes(); got != 0 {
		t.Fatalf("got %d premature writes: %q", got, dst.String())
	}

	if err := w.Flush(); err != nil {
		t.Fatalf("flush failed: %v", err)
	}

	// Batched output must arrive in order, in a single write.
	if got, want := dst.String(), "one\ntwo\n"; got != want {
		t.Errorf("got %q; want %q", got, want)
	}
	if got, want := dst.Writes(), 1; got != want {
		t.Errorf("got %d writes; want %d", got, want)
	}
}

func TestWriter_FlushesWhenFull(t *testing.T) {
	t.Parallel()

	dst := new(fakeWriter)
	w := flush.New(dst, flush.WithSize(8), flush.WithInterval(0))
	defer w.Close()

	// The second write exceeds the remaining capacity: the buffer fills
	// to its limit and is forced out, while the remainder stays behind.
	if _, err := w.Write([]byte("aaaaaa")); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if _, err := w.Write([]byte("bbbbbb")); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	if got, want := dst.String(), "aaaaaabb"; got != want {
		t.Errorf("got %q; want %q", got, want)
	}

	// Nothing may be lost across the boundary.
	if err := w.Flush(); err != nil {
		t.Fatalf("flush failed: %v", err)
	}
	if got, want := dst.String(), "aaaaaabbbbbb"; got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestWriter_FlushesOnInterval(t *testing.T) {
	t.Parallel()

	dst := new(fakeWriter)
	w := flush.New(dst, flush.WithInterval(10*time.Millisecond))
	defer w.Close()

	if _, err := w.Write([]byte("data\n")); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// The background flush must surface the data without any further
	// writes or manual flushes.
	eventually(t, func() bool {
		return dst.String() == "data\n"
	})
}

func TestWriter_Close(t *testing.T) {
	t.Parallel()

	dst := new(fakeWriter)
	w := flush.New(dst)

	if _, err := w.Write([]byte("tail\n")); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Close must drain the buffer and be idempotent.
	if err := w.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
	if got, want := dst.String(), "tail\n"; got != want {
		t.Errorf("got %q; want %q", got, want)
	}
	if err := w.Close(); err != nil {
		t.Errorf("second close failed: %v", err)
	}

	// Writes and flushes after close must be no-ops for the buffer and bypass
	// to the destination.
	if err := w.Flush(); err != nil {
		t.Errorf("flush after close failed: %v", err)
	}

	if _, err := w.Write([]byte("late\n")); err != nil {
		t.Fatalf("write after close failed: %v", err)
	}
	if got, want := dst.String(), "tail\nlate\n"; got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestWriter_Error(t *testing.T) {
	t.Parallel()

	dst := &fakeWriter{err: errors.New("disk full")}
	w := flush.New(dst, flush.WithInterval(0))
	defer w.Close()

	if _, err := w.Write([]byte("data")); err != nil {
		t.Fatalf("buffered write should not fail: %v", err)
	}
	if err := w.Flush(); err == nil {
		t.Error("flush should surface the destination error")
	}
}

func TestWriter_NilDestination(t *testing.T) {
	t.Parallel()

	w := flush.New(nil)
	defer w.Close()

	// A nil destination must discard output without panicking.
	if _, err := w.Write([]byte("data")); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("flush failed: %v", err)
	}
}

func TestWriter_Concurrent(t *testing.T) {
	t.Parallel()

	dst := new(fakeWriter)
	w := flush.New(dst,
		flush.WithSize(64),
		flush.WithInterval(time.Millisecond),
	)

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				if _, err := w.Write([]byte("line\n")); err != nil {
					t.Errorf("write failed: %v", err)
					return
				}
			}
		})
	}
	wg.Wait()

	if err := w.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	// Every line must arrive exactly once and unmangled.
	out := dst.String()
	if got, want := strings.Count(out, "line\n")*len("line\n"), len(out); got != want {
		t.Errorf("output mangled: %d of %d bytes form whole lines",
			got, want)
	}
	if got, want := strings.Count(out, "line\n"), 800; got != want {
		t.Errorf("got %d lines; want %d", got, want)
	}
}

func TestWriter_WriteString(t *testing.T) {
	t.Parallel()

	dst := new(fakeWriter)
	w := flush.New(dst, flush.WithInterval(0))

	if n, err := w.WriteString("hello "); err != nil || n != 6 {
		t.Fatalf("writing failed (%d bytes): %v", n, err)
	}
	if n, err := io.WriteString(w, "world\n"); err != nil || n != 6 {
		t.Fatalf("writing failed (%d bytes): %v", n, err)
	}

	if got := dst.Writes(); got != 0 {
		t.Fatalf("got %d premature writes: %q", got, dst.String())
	}

	if err := w.Flush(); err != nil {
		t.Fatalf("flush failed: %v", err)
	}

	if got, want := dst.String(), "hello world\n"; got != want {
		t.Errorf("got %q; want %q", got, want)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	// Invocation after close must bypass the buffer.
	if n, err := w.WriteString("after close\n"); err != nil || n != 12 {
		t.Fatalf("writing after close failed (%d bytes): %v", n, err)
	}
	if got, want := dst.String(), "hello world\nafter close\n"; got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestWriter_Observability(t *testing.T) {
	t.Parallel()

	dst := new(fakeWriter)
	bufSize := 128
	w := flush.New(dst, flush.WithSize(bufSize), flush.WithInterval(0))

	if got, want := w.Size(), bufSize; got != want {
		t.Errorf("got size %d; want %d", got, want)
	}
	if got, want := w.Buffered(), 0; got != want {
		t.Errorf("got buffered %d; want %d", got, want)
	}
	if got, want := w.Available(), bufSize; got != want {
		t.Errorf("got available %d; want %d", got, want)
	}

	data := []byte("hello observability")
	if _, err := w.Write(data); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	if got, want := w.Buffered(), len(data); got != want {
		t.Errorf("%d bytes buffered after write; want %d", got, want)
	}
	if got, want := w.Available(), bufSize-len(data); got != want {
		t.Errorf("%d bytes available after write; want %d", got, want)
	}

	if err := w.Flush(); err != nil {
		t.Fatalf("flush failed: %v", err)
	}

	if got, want := w.Buffered(), 0; got != want {
		t.Errorf("%d bytes buffered after flush; want %d", got, want)
	}
	if got, want := w.Available(), bufSize; got != want {
		t.Errorf("%d bytes available after flush; want %d", got, want)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	// After closing, the buffered and available byte count is zero, while the
	// size retains capacity.
	if got, want := w.Buffered(), 0; got != want {
		t.Errorf("%d bytes buffered after close; want %d", got, want)
	}
	if got, want := w.Available(), 0; got != want {
		t.Errorf("%d bytes available after close; want %d", got, want)
	}
	if got, want := w.Size(), bufSize; got != want {
		t.Errorf("got size %d after close; want %d", got, want)
	}
}

func TestWriter_FlushEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("empty buffer", func(t *testing.T) {
		t.Parallel()
		dst := new(fakeWriter)
		w := flush.New(dst, flush.WithInterval(0))
		defer w.Close()

		if err := w.Flush(); err != nil {
			t.Fatalf("flush on empty buffer failed: %v", err)
		}
		if exp, act := 0, dst.Writes(); act != exp {
			t.Errorf("got %d writes on empty flush; want %d", act, exp)
		}
	})

	t.Run("after close", func(t *testing.T) {
		t.Parallel()
		dst := new(fakeWriter)
		w := flush.New(dst, flush.WithInterval(0))

		if err := w.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}
		if err := w.Flush(); err != nil {
			t.Errorf("flush after close failed: %v", err)
		}
	})
}
