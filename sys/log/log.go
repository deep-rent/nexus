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
	"log/slog"
	"os"

	"github.com/deep-rent/nexus/std/ascii"
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

// ErrorKey is the attribute key under which [Err] records an error. It is
// exported so that handlers and log processors can find errors by a stable
// name.
const ErrorKey = "error"

// Err returns a [slog.Attr] carrying err under the [ErrorKey]. It is the
// canonical way to log an error in this codebase, so that every error is
// recorded under the same key and enriching that record later is a change in
// one place rather than at every call site:
//
//	logger.ErrorContext(ctx, "Failed to fetch resource", log.Err(err))
//
// A nil error yields an [slog.Attr] whose value is nil, which the handlers
// render as such; callers should log an error attribute only when there is an
// error to report.
func Err(err error) slog.Attr {
	return slog.Any(ErrorKey, err)
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
