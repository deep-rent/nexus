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
	"context"
	"slices"
	"sync"
)

// Recorder is a [Sink] that captures records in memory, letting tests
// assert on what was logged without coupling to the JSON wire format. It
// enables every level, and arguments bound via With are materialized into
// each captured record, ahead of the call-site arguments.
type Recorder struct {
	state *recorderState
	bound []Arg
}

// recorderState is the capture storage shared between a [Recorder] and
// all sinks derived from it via With.
type recorderState struct {
	mu      sync.Mutex
	records []Record
}

// NewRecorder creates an empty [Recorder].
func NewRecorder() *Recorder {
	return &Recorder{state: new(recorderState)}
}

// Enabled implements [Sink]. All defined levels are enabled.
func (r *Recorder) Enabled(_ context.Context, level Level) bool {
	return level != LevelSilent && level <= LevelDebug
}

// Receive implements [Sink]. The record's arguments are copied, so the
// captured records remain valid indefinitely.
func (r *Recorder) Receive(_ context.Context, rec Record) {
	args := make([]Arg, 0, len(r.bound)+len(rec.Args))
	args = append(args, r.bound...)
	args = append(args, rec.Args...)
	rec.Args = args

	r.state.mu.Lock()
	defer r.state.mu.Unlock()
	r.state.records = append(r.state.records, rec)
}

// With implements [Sink]. The derived sink records into the same
// [Recorder], so records logged through it are visible to
// [Recorder.Records].
func (r *Recorder) With(args []Arg) Sink {
	if len(args) == 0 {
		return r
	}
	return &Recorder{
		state: r.state,
		bound: append(slices.Clip(r.bound), args...),
	}
}

// Records returns a copy of the captured records in order of arrival.
func (r *Recorder) Records() []Record {
	r.state.mu.Lock()
	defer r.state.mu.Unlock()
	return slices.Clone(r.state.records)
}

// Reset discards the captured records.
func (r *Recorder) Reset() {
	r.state.mu.Lock()
	defer r.state.mu.Unlock()
	r.state.records = nil
}
