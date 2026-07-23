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

package log

import (
	"bytes"
	"strings"
	"sync"
)

// Buffer is a concurrency-safe [io.Writer] that captures log output for
// inspection, primarily in tests. Unlike [bytes.Buffer], it may be read
// while other goroutines are still logging. The zero value is ready for
// use.
type Buffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// Capture couples a new [Logger] to a fresh [Buffer] capturing its
// output. The buffer overrides any [WithWriter] option.
func Capture(opts ...Option) (*Logger, *Buffer) {
	b := new(Buffer)
	return New(append(opts, WithWriter(b))...), b
}

// Write implements [io.Writer].
func (b *Buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// String returns a snapshot of the captured output.
func (b *Buffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Bytes returns a copy of the captured output.
func (b *Buffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buf.Bytes())
}

// Lines splits the captured output into individual records, dropping the
// trailing newline. Since each record is a single JSON line, tests can
// assert on counts and unmarshal single elements.
func (b *Buffer) Lines() []string {
	lines := strings.Split(b.String(), "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	return lines
}

// Reset discards the captured output.
func (b *Buffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
}
