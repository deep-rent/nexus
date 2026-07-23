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
)

// Sink is the back-end of a [Logger]: it decides which records to accept
// and encodes those it receives. Implementations must be safe for
// concurrent use.
type Sink interface {
	// Enabled reports whether the sink accepts records at the given level.
	// Loggers consult it before constructing a [Record], so expensive work
	// is skipped entirely when the level is cut off.
	Enabled(ctx context.Context, level Level) bool

	// Receive handles a single record. Callers must invoke it only after
	// Enabled has reported true for the record's level. The record's Args
	// slice is only valid for the duration of the call; a sink that
	// retains arguments must copy them.
	Receive(ctx context.Context, r Record)

	// With returns a sink that includes args in every record it receives,
	// ahead of the record's own arguments. The receiver is not modified.
	// Implementations are encouraged to pre-encode the bound arguments so
	// that repeated records pay for them only once.
	With(args []Arg) Sink
}

// Multi returns a [Sink] that fans records out to all given sinks. It
// reports a level as enabled if any sink enables it, and forwards a record
// only to those sinks that do. Without arguments, it returns a sink that
// discards everything; with a single argument, it returns that sink
// unchanged.
func Multi(sinks ...Sink) Sink {
	switch len(sinks) {
	case 0:
		return discard{}
	case 1:
		return sinks[0]
	default:
		return multi{sinks: slices.Clone(sinks)}
	}
}

// multi implements the fan-out [Sink] returned by [Multi].
type multi struct {
	sinks []Sink
}

func (m multi) Enabled(ctx context.Context, level Level) bool {
	for _, s := range m.sinks {
		if s.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (m multi) Receive(ctx context.Context, r Record) {
	for _, s := range m.sinks {
		if s.Enabled(ctx, r.Level) {
			s.Receive(ctx, r)
		}
	}
}

func (m multi) With(args []Arg) Sink {
	sinks := make([]Sink, len(m.sinks))
	for i, s := range m.sinks {
		sinks[i] = s.With(args)
	}
	return multi{sinks: sinks}
}

// discard is a [Sink] that reports every level as disabled and drops any
// record it receives.
type discard struct{}

func (discard) Enabled(context.Context, Level) bool { return false }
func (discard) Receive(context.Context, Record)     {}
func (discard) With([]Arg) Sink                     { return discard{} }
