// Package log provides a convenience wrapper around Go's standard slog
// API, allowing for easy configuration of a slog.Logger instance using the
// functional options pattern.
//
// # Usage
//
// The following example demonstrates how to create a logger at debug level
// printing JSON-formatted logs to the standard output:
//
//	logger := log.New(
//		log.WithLevel("debug"),
//		log.WithFormat("json"),
//	)
//
// # Conventions
//
// Stick to the following rules to keep log output consistent:
//
//   - Format attribute keys in lower camelCase.
//   - Prefer longer keys over abbreviations (e.g., "error" over "err").
//   - Capitalize the first letter of every log message.
//   - Do not end log messages with punctuation.
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
	FormatJSON               // JSON format, suitable for structured logging.
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

	return slog.New(handler)
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

// WithLevel returns an Option that sets the minimum log level.
// It accepts either a slog.Level or a string recognized by ParseLevel.
// If the provided value is invalid, the configured level remains unchanged.
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

// WithFormat returns an Option that sets the log output format.
// It accepts either a Format or a string recognized by ParseFormat.
// If the provided value is invalid, the configured format remains unchanged.
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

// WithAddSource returns an Option that configures the logger to include
// the source code position (file and line number) in the log output.
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

// ParseLevel converts a string into a slog.Level.
// It can handle any string produced by slog.Level.MarshalText, ignoring case.
// It also accepts numeric offsets that would result in a different string on
// output. For example, "error-8" would translate to "info".
func ParseLevel(s string) (level slog.Level, err error) {
	if e := level.UnmarshalText([]byte(s)); e != nil {
		err = fmt.Errorf("invalid log level %q", s)
	}
	return
}

// ParseFormat converts a string into a Format.
// It is case-insensitive and returns an error if the string is not
// a valid format ("text" or "json").
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
