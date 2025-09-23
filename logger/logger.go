package logger

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

type Format uint8

const (
	FormatJSON Format = iota
	FormatText
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
	case FormatText:
		handler = slog.NewTextHandler(w, o)
	default:
		handler = slog.NewJSONHandler(w, o)
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

func WithLevel(level string) Option {
	return func(cfg *config) {
		cfg.Level = ParseLevel(level)
	}
}

func WithFormat(format string) Option {
	return func(cfg *config) {
		cfg.Format = ParseFormat(format)
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

func ParseLevel(s string) slog.Level {
	var level slog.Level
	_ = level.UnmarshalText([]byte(s))
	return level
}

func ParseFormat(s string) Format {
	switch strings.ToLower(s) {
	case "text":
		return FormatText
	default:
		return FormatJSON
	}
}
