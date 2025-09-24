package logger

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	DefaultLevel     = slog.LevelInfo
	DefaultAddSource = false
	DefaultFormat    = FormatText
)

// Format defines the log output format, such as JSON or plain text.
type Format uint8

const (
	FormatText Format = iota
	FormatJSON
)

func (f Format) String() string {
	switch f {
	case FormatJSON:
		return "json"
	default:
		return "text"
	}
}

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

type loggerTransport struct {
	wrapped http.RoundTripper
	log     *slog.Logger
}

func (t *loggerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	t.log.Info("Sending request", "method", req.Method, "url", req.URL)

	res, err := t.wrapped.RoundTrip(req)
	duration := time.Since(start)
	if err != nil {
		t.log.Error("Request failed", "error", err, "duration", duration)
		return nil, err
	}

	sc := res.StatusCode
	t.log.Info("Received response", "status", sc, "duration", duration)
	return res, nil
}

var _ http.RoundTripper = (*loggerTransport)(nil)

// NewTransport wraps a base transport and logs the start and end of each
// request, along with its duration. If the base transport is nil, it falls
// back to http.DefaultTransport. If the provided logger is nil, it falls back
// to slog.Default(). The resulting transport does not modify the request or
// response in any way.
func NewTransport(t http.RoundTripper, log *slog.Logger) http.RoundTripper {
	if t == nil {
		t = http.DefaultTransport
	}
	if log == nil {
		log = slog.Default()
	}
	return &loggerTransport{
		wrapped: t,
		log:     log,
	}
}
