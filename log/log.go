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
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Default configuration values for a new logger.
const (
	DefaultLevel     = slog.LevelInfo
	DefaultAddSource = false
	DefaultFormat    = FormatText
)

// Format defines the log output format, such as JSON or plain text.
type Format uint8

const (
	FormatText Format = iota // Human-readable text format.
	FormatJSON               // JSON format suitable for machine parsing.
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

// New creates and configures a new slog.Logger. By default, it logs at
// slog.LevelInfo in plain text to os.Stdout, without source information.
// These defaults can be overridden by passing in one or more Option functions.
func New(opts ...Option) *slog.Logger {
	return slog.New(NewHandler(opts...))
}

// Combine creates a new slog.Logger that broadcasts log records to multiple
// provided slog.Handlers simultaneously using slog.NewMultiHandler.
func Combine(handlers ...slog.Handler) *slog.Logger {
	return slog.New(slog.NewMultiHandler(handlers...))
}

// NewHandler creates and configures a new slog.Handler. By default, it
// sets up a text handler logging at slog.LevelInfo to os.Stdout.
// These defaults can be overridden by passing in one or more Option functions.
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
		Level:     c.Level,
		AddSource: c.AddSource,
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
	Level     slog.Level
	AddSource bool
	Format    Format
	Writer    io.Writer
}

// Option defines a function that modifies the logger configuration.
type Option func(*config)

// WithLevel sets the minimum log level. It accepts either a slog.Level constant
// (e.g., slog.LevelDebug) or a case-insensitive string (e.g., "debug") as
// handled by ParseLevel. If an invalid string or type is provided, the option
// is a no-op.
func WithLevel(v any) Option {
	return func(c *config) {
		switch t := v.(type) {
		case slog.Level:
			c.Level = t
		case string:
			level, err := ParseLevel(t)
			if err == nil {
				c.Level = level
			}
		}
	}
}

// WithFormat sets the log output format. It accepts either a Format constant
// (FormatText or FormatJSON) or a case-insensitive string ("text" or "json")
// as handled by ParseFormat. If an invalid string or type is provided, the
// option is a no-op.
func WithFormat(v any) Option {
	return func(c *config) {
		switch t := v.(type) {
		case Format:
			c.Format = t
		case string:
			format, err := ParseFormat(t)
			if err == nil {
				c.Format = format
			}
		}
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

// WithWriter returns an Option that sets the output destination for the logs.
// If the provided io.Writer is nil, it is ignored.
func WithWriter(w io.Writer) Option {
	return func(c *config) {
		if w != nil {
			c.Writer = w
		}
	}
}

// ParseLevel converts a case-insensitive string into a slog.Level.
// It accepts standard level names like "debug", "info", "warn", and "error".
// It returns an error if the string is not a valid level.
func ParseLevel(s string) (level slog.Level, err error) {
	if e := level.UnmarshalText([]byte(s)); e != nil {
		err = fmt.Errorf("invalid log level %q", s)
	}
	return
}

// ParseFormat converts a case-insensitive string into a Format.
// Valid inputs are "text" and "json". It returns an error for any other value.
func ParseFormat(s string) (format Format, err error) {
	switch strings.ToLower(s) {
	case "json":
		format = FormatJSON
		return
	case "text":
		format = FormatText
		return
	default:
		err = fmt.Errorf("invalid log format %q", s)
		return
	}
}

// Silent creates a logger that discards all output.
func Silent() *slog.Logger {
	const LevelSilent = slog.Level(100)
	return New(
		WithWriter(io.Discard),
		WithLevel(LevelSilent),
	)
}
