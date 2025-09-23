package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Format defines the log output format, such as JSON or plain text.
type Format uint8

const (
	// FormatJSON specifies that log entries should be formatted as JSON.
	// This is the default format.
	FormatText Format = iota
	// FormatText specifies that log entries should be formatted as plain text.
	FormatJSON
)

func New(opts ...Option) *slog.Logger {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	w := cfg.Writer
	o := &slog.HandlerOptions{
		Level:     cfg.Level,
		AddSource: cfg.AddSource,
	}

	var handler slog.Handler
	switch cfg.Format {
	case FormatJSON:
		handler = slog.NewJSONHandler(w, o)
	default:
		handler = slog.NewTextHandler(w, o)
	}

	return slog.New(handler)
}

type config struct {
	Level     slog.Level
	AddSource bool
	Format    Format
	Writer    io.Writer
}

func defaultConfig() config {
	return config{
		Writer: os.Stdout,
	}
}

type Option func(*config)

func WithLevel(name string) Option {
	return func(cfg *config) {
		if level, err := ParseLevel(name); err == nil {
			cfg.Level = level
		}
	}
}

func WithFormat(name string) Option {
	return func(cfg *config) {
		if format, err := ParseFormat(name); err == nil {
			cfg.Format = format
		}
	}
}

func WithAddSource(add bool) Option {
	return func(cfg *config) {
		cfg.AddSource = add
	}
}

func WithWriter(w io.Writer) Option {
	return func(cfg *config) {
		if w != nil {
			cfg.Writer = w
		}
	}
}

func ParseLevel(s string) (level slog.Level, err error) {
	if e := level.UnmarshalText([]byte(s)); e != nil {
		err = fmt.Errorf("invalid log level %q", s)
	}
	return
}

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
