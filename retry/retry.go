package retry

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/deep-rent/nexus/backoff"
	"github.com/deep-rent/nexus/header"
)

type Attempt struct {
	Request  *http.Request
	Response *http.Response
	Error    error
	Count    int
}

func (a Attempt) Idempotent() bool {
	switch a.Request.Method {
	case
		http.MethodGet,
		http.MethodHead,
		http.MethodOptions,
		http.MethodTrace,
		http.MethodPut,
		http.MethodDelete:
		return true
	default:
		return false
	}
}

func (a Attempt) Temporary() bool {
	if a.Response != nil {
		switch a.Response.StatusCode {
		case
			http.StatusRequestTimeout,      // 408
			http.StatusTooManyRequests,     // 429
			http.StatusInternalServerError, // 500
			http.StatusBadGateway,          // 502
			http.StatusServiceUnavailable,  // 503
			http.StatusGatewayTimeout:      // 504
			return true
		}
	}
	return false
}

func (a Attempt) Transient() bool {
	if a.Error == nil ||
		errors.Is(a.Error, context.Canceled) ||
		errors.Is(a.Error, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(a.Error, io.ErrUnexpectedEOF) || errors.Is(a.Error, io.EOF) {
		return true
	}
	var err net.Error
	return errors.As(a.Error, &err) && err.Timeout()
}

type Policy func(a Attempt) bool

func (p Policy) LimitAttempts(n int) Policy {
	if n <= 0 {
		return p
	}
	return func(a Attempt) bool {
		return a.Count < n && p(a)
	}
}

func DefaultPolicy() Policy {
	return func(a Attempt) bool {
		return a.Idempotent() && (a.Temporary() || a.Transient())
	}
}

type transport struct {
	next    http.RoundTripper
	policy  Policy
	backoff backoff.Strategy
	logger  *slog.Logger
	now     func() time.Time
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	var (
		res   *http.Response
		err   error
		count int
	)

	defer t.backoff.Done()
	rewindable := req.GetBody != nil
	for {
		count++

		// If this is a retry and the body is rewindable, obtain a new reader
		if count > 1 && rewindable {
			var e error
			req.Body, e = req.GetBody()
			if e != nil {
				// Cannot rewind the body, so we must stop here
				return nil, e
			}
		}

		res, err = t.next.RoundTrip(req)
		// If the request body is not rewindable, we cannot retry
		if req.Body != nil && !rewindable {
			break
		}

		// Ask the policy if we should retry
		if !t.policy(Attempt{
			Request:  req,
			Response: res,
			Error:    err,
			Count:    count,
		}) {
			break // Success or policy decided to stop
		}

		// If retrying, drain and close the previous response body
		if res != nil && res.Body != nil {
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
		}

		delay := t.backoff.Next()
		if res != nil {
			if d := header.Throttle(res.Header, t.now); d != 0 {
				// Use the longer of the two delays to respect both the server
				// and our own backoff policy
				delay = max(delay, d)
			}
		}

		if ctx := req.Context(); t.logger.Enabled(ctx, slog.LevelDebug) {
			attrs := []any{
				slog.Int("attempt", count),
				slog.Duration("delay", delay),
				slog.String("method", req.Method),
				slog.String("url", req.URL.String()),
			}
			if err != nil {
				attrs = append(attrs, slog.Any("error", err))
			}
			if res != nil {
				attrs = append(attrs, slog.Int("status", res.StatusCode))
			}

			t.logger.DebugContext(ctx, "Request attempt failed, retrying", attrs...)
		}

		if delay <= 0 {
			continue // Retry without delay
		}

		// Wait for the delay, respecting context cancellation
		select {
		case <-time.After(delay):
			continue // Proceed to next attempt
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}

	return res, err
}

var _ http.RoundTripper = (*transport)(nil)

func NewTransport(
	next http.RoundTripper,
	opts ...Option,
) http.RoundTripper {
	c := config{
		policy:  DefaultPolicy(),
		limit:   0,
		backoff: backoff.Constant(0),
		logger:  slog.Default(),
	}
	for _, opt := range opts {
		opt(&c)
	}
	return &transport{
		next:    next,
		policy:  c.policy.LimitAttempts(c.limit),
		backoff: c.backoff,
		now:     c.now,
	}
}

type config struct {
	policy  Policy
	limit   int
	backoff backoff.Strategy
	logger  *slog.Logger
	now     func() time.Time
}

type Option func(*config)

func WithPolicy(policy Policy) Option {
	return func(c *config) {
		if policy != nil {
			c.policy = policy
		}
	}
}

func WithAttemptLimit(n int) Option {
	return func(c *config) {
		c.limit = n
	}
}

func WithBackoff(strategy backoff.Strategy) Option {
	return func(c *config) {
		if strategy != nil {
			c.backoff = strategy
		}
	}
}

func WithLogger(log *slog.Logger) Option {
	return func(c *config) {
		if log != nil {
			c.logger = log
		}
	}
}

func WithClock(now func() time.Time) Option {
	return func(c *config) {
		if now != nil {
			c.now = now
		}
	}
}
