package logger

import (
	"log/slog"
	"os"
	"strings"
)

func New(s string) *slog.Logger {
	level := slog.LevelInfo // Default level
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	return slog.New(slog.NewJSONHandler(
		os.Stdout,
		&slog.HandlerOptions{
			Level: level,
		}),
	)
}
