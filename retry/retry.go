// Package retry is an http.RoundTripper middleware that provides automatic,
// policy-driven retries for HTTP requests.
//
// It wraps an existing http.RoundTripper (such as http.DefaultTransport)
// and intercepts requests to apply retry logic. The decision to retry is
// controlled by a Policy, and the delay between attempts is determined by a
// backoff.Strategy.
//
// # Usage
//
// A new transport is created with NewTransport, configured with functional
// options like WithAttemptLimit and WithBackoff.
//
// Example:
//
//	// Retry up to 3 times with exponential backoff starting at 1 second.
//	transport := retry.NewTransport(
//		http.DefaultTransport,
//		retry.WithAttemptLimit(3),
//		retry.WithBackoff(backoff.New(
//			backoff.WithMinDelay(1*time.Second),
//		)),
//	)
//
//	client := &http.Client{Transport: transport}
//
//	// This request will be retried automatically on temporary failures.
//	res, err := client.Get("http://example.com/flaky")
//	if err != nil {
//		slog.Error("Request failed after all retries", "error", err)
//		return
//	}
//	defer res.Body.Close()
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

// Attempt encapsulates the state of a single HTTP request attempt. It is passed
// to a Policy to determine if a retry is warranted.
type Attempt struct {
	Request  *http.Request
	Response *http.Response
	Error    error
	Count    int
}

// Idempotent reports whether the request can be safely retried without
// unintended side effects. It considers standard HTTP methods that are
// idempotent according to RFC 7231.
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

// Temporary reports whether the response indicates a server-side temporary
// failure. This is determined by specific HTTP status codes that suggest the
// request might succeed if retried.
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

// Transient reports whether the error suggests a temporary network-level
// issue that might be resolved on a subsequent attempt. It returns true for
// network timeouts and unexpected EOF errors.
//
// It returns false for context cancellations (context.Canceled,
// context.DeadlineExceeded), as these are intentional and should not be
// retried.
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

// Policy is the central decision-making function that determines whether a
// request should be retried. It is invoked after each attempt with the
// corresponding Attempt details. It returns true to schedule a retry or false
// to stop and return the last response/error.
type Policy func(a Attempt) bool

// LimitAttempts decorates a Policy to enforce a maximum attempt limit.
//
// It short-circuits the decision, returning false if the attempt count has
// reached the limit n. Otherwise, it delegates the decision to the wrapped
// policy. A limit of n means a request will be attempted at most n times
// (e.g., an initial attempt and n-1 retries). A limit of 1 disables retries.
func (p Policy) LimitAttempts(n int) Policy {
	if n <= 0 {
		return p
	}
	return func(a Attempt) bool {
		return a.Count < n && p(a)
	}
}

// DefaultPolicy provides a safe and sensible default retry strategy. It enters
// the retry loop only for idempotent requests that have resulted in a
// temporary server error or a transient network error such as a timeout.
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

// RoundTrip executes a single HTTP transaction, applying retry logic as
// configured. It is the implementation of the http.RoundTripper interface.
//
// For a request to be retryable, its body must be rewindable. This is
// achieved by setting the http.Request.GetBody field. If GetBody is nil,
// the request is attempted only once, as its body stream cannot be read
// a second time.
//
// RoundTrip is responsible for handling the response body. On a successful
// attempt (or the final failed attempt), the response body is returned to the
// caller, who is responsible for closing it. On intermediary failed attempts,
// the response body is fully read and closed to ensure the underlying
// connection can be reused.
//
// The retry loop is sensitive to the request's context. If the context is
// cancelled, the retry loop terminates immediately.
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

		// If this is a retry and the body is rewindable, obtain a new reader.
		if count > 1 && rewindable {
			var e error
			req.Body, e = req.GetBody()
			if e != nil {
				// Cannot rewind the body, so we must stop here.
				return nil, e
			}
		}

		res, err = t.next.RoundTrip(req)

		// Ask the policy if we should retry.
		if !t.policy(Attempt{
			Request:  req,
			Response: res,
			Error:    err,
			Count:    count,
		}) {
			break // Success or policy decided to exit
		}

		// Check if the request body is rewindable. If not, we must stop here.
		// This is checked after the policy to ensure the policy still gets notified
		// of the attempt.
		if req.Body != nil && !rewindable {
			break
		}

		// If retrying, drain and close the previous response body.
		if res != nil && res.Body != nil {
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
		}

		delay := t.backoff.Next()
		if res != nil {
			if d := header.Throttle(res.Header, t.now); d != 0 {
				// Use the longer of the two delays to respect both the server
				// and our own backoff policy.
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

		// Wait for the delay, respecting context cancellation.
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

// NewTransport creates and returns a new retrying http.RoundTripper. It wraps
// an existing transport and retries requests based on the configured policy
// and backoff strategy.
func NewTransport(
	next http.RoundTripper,
	opts ...Option,
) http.RoundTripper {
	cfg := config{
		policy:  DefaultPolicy(),
		limit:   0,
		backoff: backoff.Constant(0),
		logger:  slog.Default(),
		now:     time.Now,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	return &transport{
		next:    next,
		policy:  cfg.policy.LimitAttempts(cfg.limit),
		backoff: cfg.backoff,
		logger:  cfg.logger,
		now:     cfg.now,
	}
}

type config struct {
	policy  Policy
	limit   int
	backoff backoff.Strategy
	logger  *slog.Logger
	now     func() time.Time
}

// Option is a function that configures the retry transport.
type Option func(*config)

// WithPolicy sets the retry policy used by the transport. If not provided,
// DefaultPolicy is used. A nil value is ignored.
func WithPolicy(policy Policy) Option {
	return func(c *config) {
		if policy != nil {
			c.policy = policy
		}
	}
}

// WithAttemptLimit sets the maximum number of attempts for a request, including
// the initial one. A value of 3 means one initial attempt and up to two
// retries. A value of 1 effectively disables retries. If the value is 0 or
// less, no limit is enforced and retries are governed solely by the policy.
func WithAttemptLimit(n int) Option {
	return func(c *config) {
		c.limit = n
	}
}

// WithBackoff sets the backoff strategy for calculating the delay between
// retries. If not provided, there is no delay between attempts. A nil value is
// ignored.
func WithBackoff(strategy backoff.Strategy) Option {
	return func(c *config) {
		if strategy != nil {
			c.backoff = strategy
		}
	}
}

// WithLogger sets the logger for debug messages. If not provided,
// slog.Default() is used. A nil value is ignored.
func WithLogger(log *slog.Logger) Option {
	return func(c *config) {
		if log != nil {
			c.logger = log
		}
	}
}

// WithClock provides a custom time source, primarily for testing. If not
// provided, time.Now is used. A nil value is ignored.
func WithClock(now func() time.Time) Option {
	return func(c *config) {
		if now != nil {
			c.now = now
		}
	}
}
