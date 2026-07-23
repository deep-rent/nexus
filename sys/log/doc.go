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

// Package log implements a strict, structured logging facility.
//
// Records are emitted as JSON lines only. There is no text format, no
// reflection-based encoding, and no package-level default logger; loggers
// arrive by injection. Every call takes a [context.Context], and values are
// attached as typed key/value pairs built with constructors such as
// [String], [Int], and [Err].
//
// # Usage
//
// Create a logger that writes JSON lines to standard error at debug level:
//
//	logger := log.New(
//		log.WithLevel(log.LevelDebug),
//		log.WithWriter(os.Stderr),
//	)
//	logger.Info(ctx, "Server started", log.Int("port", 8080))
//
// Loggers are hierarchical: [Logger.Child] derives a named sub-logger whose
// dotted path is recorded under the "logger" key, and [Logger.With] returns
// a logger that includes the given arguments in every record. Bound
// arguments are encoded once, not on every call, so per-request loggers are
// cheap:
//
//	web := logger.Child("http").With(log.String("request_id", id))
//	web.Debug(ctx, "Request received", log.String("path", r.URL.Path))
//
// # Levels
//
// The level set is fixed: [LevelError], [LevelWarn], [LevelInfo], and
// [LevelDebug], plus [LevelSilent], a configuration-only threshold that
// disables output entirely. There is deliberately no designated fatal or panic
// level; a logger that terminates the process skips deferred cleanup and cannot
// be tested. If a catastrophic error occurs, log it and exit.
//
// The threshold can be adjusted at runtime through a shared [Cutoff], and
// overridden per request with [SetLevel]:
//
//	ctx = log.SetLevel(ctx, log.LevelDebug)
//
// # Sinks
//
// The [Logger] front-end is fixed policy; the [Sink] interface is the
// extension point. [NewSink] returns the JSON sink, [Multi] fans records
// out to several sinks, and [Discard] returns a logger that reports every
// level as disabled, so callers guarding expensive work with
// [Logger.Enabled] skip it entirely.
//
// # Testing
//
// [Capture] couples a logger to a concurrency-safe [Buffer] for
// asserting on the emitted JSON, and [Recorder] is a [Sink] that captures
// [Record] values in memory for structural assertions that do not depend
// on the wire format.
package log
