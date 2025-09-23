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
	FormatText Format = iota
	FormatJSON
)

func New(opts ...Option) *slog.Logger {
	c := config{
		Level:     slog.LevelInfo,
		AddSource: false,
		Format:    FormatText,
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

type config struct {
	Level     slog.Level
	AddSource bool
	Format    Format
	Writer    io.Writer
}

type Option func(*config)

func WithLevel(name string) Option {
	return func(c *config) {
		if level, err := ParseLevel(name); err == nil {
			c.Level = level
		}
	}
}

func WithFormat(name string) Option {
	return func(c *config) {
		if format, err := ParseFormat(name); err == nil {
			c.Format = format
		}
	}
}

func WithAddSource(add bool) Option {
	return func(c *config) {
		c.AddSource = add
	}
}

func WithWriter(w io.Writer) Option {
	return func(c *config) {
		if w != nil {
			c.Writer = w
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
