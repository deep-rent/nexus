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

package flush

import (
	"bufio"
	"io"
	"sync"
	"time"
)

// Writer is a buffered [io.Writer] that batches writes to an underlying
// destination and flushes them when the buffer fills, when the configured
// interval elapses, or on [Writer.Flush] and [Writer.Close]. It is safe
// for concurrent use.
type Writer struct {
	mu     sync.Mutex
	dst    io.Writer
	buf    *bufio.Writer
	closed bool

	done chan struct{}
	wg   sync.WaitGroup
	once sync.Once
}

// New creates a [Writer] forwarding to dst. By default, it buffers up to
// [DefaultSize] bytes and flushes every [DefaultInterval]. These defaults
// can be overridden by passing in one or more [Option] functions. A nil
// destination discards all output.
func New(dst io.Writer, opts ...Option) *Writer {
	c := config{
		size:     DefaultSize,
		interval: DefaultInterval,
	}
	for _, opt := range opts {
		opt(&c)
	}

	if dst == nil {
		dst = io.Discard
	}

	w := &Writer{
		dst:  dst,
		buf:  bufio.NewWriterSize(dst, c.size),
		done: make(chan struct{}),
	}
	if c.interval > 0 {
		w.wg.Add(1)
		go w.loop(c.interval)
	}
	return w
}

// loop flushes the buffer periodically until the writer is closed.
func (w *Writer) loop(interval time.Duration) {
	defer w.wg.Done()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			// A write error has nowhere to be reported here; it sticks
			// in the buffer and surfaces on the next Write or Flush.
			_ = w.Flush()
		case <-w.done:
			return
		}
	}
}

// Write implements [io.Writer]. The data is buffered; any error returned
// stems from a flush of previously buffered data to the destination.
// After [Writer.Close], writes bypass the buffer and go directly to the
// destination.
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return w.dst.Write(p)
	}
	return w.buf.Write(p)
}

// WriteString implements [io.StringWriter]. It forwards strings to the
// underlying writer.
func (w *Writer) WriteString(s string) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return io.WriteString(w.dst, s)
	}
	return w.buf.WriteString(s)
}

// Flush forwards all buffered data to the destination.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	return w.buf.Flush()
}

// Close stops the background flushing and drains the buffer. It reports
// the error of the final flush; subsequent calls return nil. The
// destination is left open, since the writer does not own it.
func (w *Writer) Close() (err error) {
	w.once.Do(func() {
		close(w.done)
		w.wg.Wait()

		w.mu.Lock()
		defer w.mu.Unlock()
		err = w.buf.Flush()
		w.closed = true
	})
	return err
}

// Size returns the capacity of the underlying buffer in bytes.
func (w *Writer) Size() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Size()
}

// Buffered returns the number of bytes currently stored in the buffer.
func (w *Writer) Buffered() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0
	}
	return w.buf.Buffered()
}

// Available returns how many bytes are unused in the buffer.
func (w *Writer) Available() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0
	}
	return w.buf.Available()
}

var (
	_ io.Writer       = (*Writer)(nil)
	_ io.StringWriter = (*Writer)(nil)
)

