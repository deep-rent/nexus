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

// Package log provides a configurable constructor for the standard
// [slog.Logger], allowing for easy setup using the functional options pattern.
// It simplifies the creation of a structured logger by abstracting away the
// handler setup and providing flexible options for setting the level, format,
// and output from common types like strings.
//
// # Usage
//
// Create a logger that outputs JSON at a debug level to standard error:
//
// Example:
//
//	logger := log.New(
//	  log.WithLevel(slog.LevelDebug),
//	  log.WithFormat(log.FormatJSON),
//	  log.WithWriter(os.Stderr),
//	  log.WithAddSource(true), // Include file and line number.
//	)
//
// Levels and formats can also be parsed from configuration strings with
// [ParseLevel] and [ParseFormat].
//
//	slog.SetDefault(logger)
//	slog.Debug("This is a debug message")
//
// Create a multi-target logger using Combine and NewHandler:
//
// Example:
//
//	h1 := log.NewHandler(
//	  log.WithLevel(slog.LevelDebug),
//	  log.WithFormat(FormatText),
//	  log.WithWriter(os.Stdout),
//	)
//	h2 := log.NewHandler(
//	  log.WithLevel(slog.LevelError),
//	  log.WithFormat(FormatJSON),
//	  log.WithWriter(os.Stderr),
//	)
//	multiLogger := log.Combine(h1, h2)
//
//	slog.SetDefault(multiLogger)
//	slog.Debug("This is a debug message")
package log

import (
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/deep-rent/nexus/internal/ascii"
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

// Format defines the log output format, such as JSON or plain text.
type Format uint8

const (
	// FormatText produces human-readable text format.
	FormatText Format = iota
	// FormatJSON produces JSON format suitable for machine parsing.
	FormatJSON
)

// String returns the lower-case string representation of the log format.
func (f Format) String() string {
	switch f {
	case FormatJSON:
		return "json"
	default:
		return "text"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (f Format) MarshalText() ([]byte, error) {
	switch f {
	case FormatText:
		return []byte("text"), nil
	case FormatJSON:
		return []byte("json"), nil
	default:
		return nil, fmt.Errorf("invalid log format %d", f)
	}
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (f *Format) UnmarshalText(text []byte) error {
	switch ascii.ToLower(string(text)) {
	case "json":
		*f = FormatJSON
		return nil
	case "text":
		*f = FormatText
		return nil
	default:
		return fmt.Errorf("invalid log format %q", text)
	}
}

// New creates and configures a new [slog.Logger]. By default, it logs at
// [slog.LevelInfo] in plain text to [os.Stdout], without source information.
// These defaults can be overridden by passing in one or more [Option]
// functions.
func New(opts ...Option) *slog.Logger {
	return slog.New(NewHandler(opts...))
}

// Combine creates a new [slog.Logger] that broadcasts log records to multiple
// provided [slog.Handler] instances simultaneously using
// [slog.NewMultiHandler].
func Combine(handlers ...slog.Handler) *slog.Logger {
	return slog.New(slog.NewMultiHandler(handlers...))
}

// NewHandler creates and configures a new [slog.Handler]. By default, it
// sets up a text handler logging at [slog.LevelInfo] to [os.Stdout].
// These defaults can be overridden by passing in one or more [Option]
// functions.
func NewHandler(opts ...Option) slog.Handler {
	c := config{
		Level:     DefaultLevel,
		AddSource: DefaultAddSource,
		Format:    DefaultFormat,
		Writer:    os.Stdout,
	}
	for _, opt := range opts {
		opt(&c)
	}

	w := c.Writer
	o := &slog.HandlerOptions{
		Level:       c.Level,
		AddSource:   c.AddSource,
		ReplaceAttr: c.ReplaceAttr,
	}

	var handler slog.Handler
	switch c.Format {
	case FormatJSON:
		handler = slog.NewJSONHandler(w, o)
	default:
		handler = slog.NewTextHandler(w, o)
	}

	return handler
}

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

// ParseLevel converts a case-insensitive string into a [slog.Level].
// It accepts standard level names like "debug", "info", "warn", and "error".
// It returns an error if the string is not a valid level.
func ParseLevel(s string) (level slog.Level, err error) {
	if e := level.UnmarshalText([]byte(s)); e != nil {
		err = fmt.Errorf("invalid log level %q", s)
	}
	return level, err
}

// ParseFormat converts a case-insensitive string into a [Format].
// Valid inputs are "text" and "json". It returns an error for any other value.
func ParseFormat(s string) (format Format, err error) {
	err = format.UnmarshalText([]byte(s))
	return format, err
}

// Silent creates a logger that discards all output. Unlike a logger pointed
// at [io.Discard], it reports every level as disabled, so a caller guarding
// expensive work with [slog.Logger.Enabled] skips it entirely.
func Silent() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}
