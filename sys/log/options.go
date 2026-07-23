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
	"io"
)

// DefaultLevel is the threshold used when none is specified.
const DefaultLevel = LevelInfo

// config holds the configuration settings for the JSON sink.
type config struct {
	// level is the initial threshold; ignored if cutoff is set.
	level Level
	// cutoff is a shared, externally adjustable threshold.
	cutoff *Cutoff
	// writer is the output destination.
	writer io.Writer
	// redact lists keys whose values are masked on output.
	redact []string
	// derive derives ambient arguments from the context of each record.
	derive func(ctx context.Context, args []Arg) []Arg
}

// Option defines a function that modifies the JSON sink configuration.
type Option func(*config)

// WithLevel sets the minimum log level. The sink owns a private [Cutoff]
// initialized to this level; use [WithCutoff] instead to share an
// adjustable threshold, in which case this option is ignored.
func WithLevel(level Level) Option {
	return func(c *config) {
		c.level = level
	}
}

// WithCutoff shares an externally adjustable threshold with the sink,
// overriding [WithLevel]. A nil cutoff is ignored.
func WithCutoff(cutoff *Cutoff) Option {
	return func(c *config) {
		if cutoff != nil {
			c.cutoff = cutoff
		}
	}
}

// WithWriter sets the output destination for the logs. The sink
// serializes its writes, so the writer need not be safe for concurrent
// use. A nil writer is ignored.
//
// The sink issues one write per record. High-volume deployments where
// the resulting system calls show up in profiles can wrap the
// destination in a [github.com/deep-rent/nexus/std/flush.Writer] to
// batch them, trading a bounded loss window on a crash.
func WithWriter(w io.Writer) Option {
	return func(c *config) {
		if w != nil {
			c.writer = w
		}
	}
}

// WithRedact masks the value of any argument whose key matches one of the
// given names with a fixed marker. Key comparison is case-insensitive,
// since header- and field-derived keys vary in casing. Repeated use adds
// to the set.
//
//	log.New(log.WithRedact("authorization", "password", "set-cookie"))
//
// Redaction applies to call-site arguments and to arguments bound with
// [Logger.With] alike. It guards accidental leaks; it is not a substitute
// for not logging secrets in the first place.
func WithRedact(keys ...string) Option {
	return func(c *config) {
		c.redact = append(c.redact, keys...)
	}
}

// WithContextArgs sets a function that derives ambient arguments, such as
// a trace or request ID, from the context of each record. The function
// appends to args and returns the result; it runs after the level check,
// once per emitted record. A nil function is ignored.
//
//	log.New(log.WithContextArgs(
//		func(ctx context.Context, args []log.Arg) []log.Arg {
//			if id, ok := trace.FromContext(ctx); ok {
//				args = append(args, log.String("trace_id", id))
//			}
//			return args
//		},
//	))
func WithContextArgs(fn func(ctx context.Context, args []Arg) []Arg) Option {
	return func(c *config) {
		if fn != nil {
			c.derive = fn
		}
	}
}
