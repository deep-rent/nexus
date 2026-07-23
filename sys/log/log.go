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
	"time"
)

// Logger is the front-end of the logging facility. It is a concrete type
// on purpose: the policy it enforces, such as leveled, context-aware calls
// and typed arguments, is fixed, while extension happens behind the [Sink]
// interface. Loggers are immutable and safe for concurrent use; methods
// like [Logger.Child] and [Logger.With] derive new loggers rather than
// modifying the receiver.
//
// Methods must not be called on a nil Logger; use [Discard] for a logger
// that is deliberately inert.
type Logger struct {
	sink   Sink
	name   string
	path   string
	parent *Logger
}

// New creates a root [Logger] backed by the JSON sink returned by
// [NewSink] with the same options. By default, it logs at [LevelInfo] to
// [os.Stdout].
func New(opts ...Option) *Logger {
	return Wrap(NewSink(opts...))
}

// Wrap creates a root [Logger] on top of an arbitrary [Sink]. A nil sink
// yields a logger that discards everything.
func Wrap(sink Sink) *Logger {
	if sink == nil {
		sink = discard{}
	}
	return &Logger{sink: sink}
}

// discardLogger backs [Discard]. It is shared; loggers are immutable.
var discardLogger = &Logger{sink: discard{}}

// Discard returns a logger that reports every level as disabled and drops
// all records. It is the explicit value for optional logger fields; unlike
// a logger pointed at a discarding writer, callers guarding expensive work
// with [Logger.Enabled] skip it entirely.
func Discard() *Logger {
	return discardLogger
}

// Sink returns the sink backing the logger.
func (l *Logger) Sink() Sink {
	return l.sink
}

// Name returns the last segment of the logger's path, such as "server"
// for the logger "http.server". It is empty for the root logger.
func (l *Logger) Name() string {
	return l.name
}

// Path returns the dotted path of the logger, such as "http.server". It
// is empty for the root logger.
func (l *Logger) Path() string {
	return l.path
}

// Parent returns the logger this logger was derived from by
// [Logger.Child], or nil for a root logger.
func (l *Logger) Parent() *Logger {
	return l.parent
}

// Child derives a named sub-logger. The child shares the parent's sink,
// and its dotted path, recorded under the "logger" key of every record,
// extends the parent's path by the given name. An empty name returns the
// receiver unchanged.
func (l *Logger) Child(name string) *Logger {
	if name == "" {
		return l
	}
	path := name
	if l.path != "" {
		path = l.path + "." + name
	}
	return &Logger{sink: l.sink, name: name, path: path, parent: l}
}

// With returns a logger that includes the given arguments in every
// record, ahead of the arguments passed at the call site. The bound
// arguments are pre-encoded by the JSON sink, so they are paid for once
// rather than on every call. Without arguments, the receiver is returned
// unchanged.
func (l *Logger) With(args ...Arg) *Logger {
	if len(args) == 0 {
		return l
	}
	c := *l
	c.sink = l.sink.With(args)
	return &c
}

// Enabled reports whether a record at the given level would be emitted.
// Use it to guard work that is expensive even before its result is passed
// to the logger:
//
//	if logger.Enabled(ctx, log.LevelDebug) {
//		logger.Debug(ctx, "State dump", log.String("state", dump()))
//	}
func (l *Logger) Enabled(ctx context.Context, level Level) bool {
	if level == LevelSilent || level > LevelDebug {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return l.sink.Enabled(ctx, level)
}

// Log emits a record at the given level. Records at [LevelSilent] or at
// levels outside the defined range are discarded. A nil context is
// replaced by [context.Background].
func (l *Logger) Log(
	ctx context.Context,
	level Level,
	msg string,
	args ...Arg,
) {
	l.log(ctx, level, msg, args)
}

// Error emits a record at [LevelError].
func (l *Logger) Error(ctx context.Context, msg string, args ...Arg) {
	l.log(ctx, LevelError, msg, args)
}

// Warn emits a record at [LevelWarn].
func (l *Logger) Warn(ctx context.Context, msg string, args ...Arg) {
	l.log(ctx, LevelWarn, msg, args)
}

// Info emits a record at [LevelInfo].
func (l *Logger) Info(ctx context.Context, msg string, args ...Arg) {
	l.log(ctx, LevelInfo, msg, args)
}

// Debug emits a record at [LevelDebug].
func (l *Logger) Debug(ctx context.Context, msg string, args ...Arg) {
	l.log(ctx, LevelDebug, msg, args)
}

// log implements the emission path shared by all logging methods. The
// timestamp is taken only after the level check, so disabled calls cost
// little more than a branch.
func (l *Logger) log(ctx context.Context, level Level, msg string, args []Arg) {
	if level == LevelSilent || level > LevelDebug {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if !l.sink.Enabled(ctx, level) {
		return
	}
	l.sink.Receive(ctx, Record{
		Time:   time.Now(),
		Level:  level,
		Logger: l.path,
		Msg:    msg,
		Args:   args,
	})
}
