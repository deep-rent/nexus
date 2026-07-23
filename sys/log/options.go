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
	"io"
	"log/slog"

	"github.com/deep-rent/nexus/std/ascii"
)

// Default configuration values for a new logger.
const (
	// DefaultLevel is the level used when none is specified.
	DefaultLevel = slog.LevelInfo
	// DefaultAddSource is the default setting for including source information.
	DefaultAddSource = false
	// DefaultFormat is the format used when none is specified.
	DefaultFormat = FormatText
)

// config holds the configuration settings for the logger.
type config struct {
	// Level is the minimum log level enabled.
	Level slog.Level
	// AddSource determines if file/line information is included.
	AddSource bool
	// Format determines the output encoding.
	Format Format
	// Writer is the output destination.
	Writer io.Writer
	// ReplaceAttr rewrites or drops attributes before they are logged.
	ReplaceAttr func(groups []string, a slog.Attr) slog.Attr
}

// Option defines a function that modifies the logger configuration.
type Option func(*config)

// WithLevel sets the minimum log level.
func WithLevel(level slog.Level) Option {
	return func(c *config) {
		c.Level = level
	}
}

// WithFormat sets the log output format.
func WithFormat(format Format) Option {
	return func(c *config) {
		c.Format = format
	}
}

// WithAddSource configures the logger to include the source code position (file
// and line number) in each log entry.
//
// Note that this has a performance cost and should be used judiciously, often
// enabled only during development or at debug levels.
func WithAddSource(add bool) Option {
	return func(c *config) {
		c.AddSource = add
	}
}

// WithWriter returns an [Option] that sets the output destination for the logs.
// If the provided [io.Writer] is nil, it is ignored.
func WithWriter(w io.Writer) Option {
	return func(c *config) {
		if w != nil {
			c.Writer = w
		}
	}
}

// WithReplaceAttr sets a function that is called for every non-group
// attribute before it is written, letting the caller rewrite or drop it. It
// maps directly onto [slog.HandlerOptions.ReplaceAttr].
//
// The common use is redaction: keeping secrets out of the logs regardless of
// what a call site passes. A nil function is ignored.
//
//	log.New(log.WithReplaceAttr(func(_ []string, a slog.Attr) slog.Attr {
//		switch a.Key {
//		case "authorization", "password", "token":
//			return slog.String(a.Key, "[REDACTED]")
//		default:
//			return a
//		}
//	}))
//
// Redaction guards accidental leaks; it is not a substitute for not logging
// secrets in the first place.
func WithReplaceAttr(
	fn func(groups []string, a slog.Attr) slog.Attr,
) Option {
	return func(c *config) {
		if fn != nil {
			c.ReplaceAttr = fn
		}
	}
}

// Redact returns a [WithReplaceAttr] option that replaces the value of any
// attribute whose key matches one of the given names with a fixed marker. Key
// comparison is case-insensitive, since header- and field-derived keys vary
// in casing.
//
//	log.New(log.Redact("authorization", "password", "set-cookie"))
//
// Only top-level keys are matched; an attribute nested inside a group is
// compared by its own key, not its group-qualified path.
func Redact(keys ...string) Option {
	set := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		set[ascii.ToLower(k)] = struct{}{}
	}
	return WithReplaceAttr(func(_ []string, a slog.Attr) slog.Attr {
		if _, ok := set[ascii.ToLower(a.Key)]; ok {
			return slog.String(a.Key, "[REDACTED]")
		}
		return a
	})
}
