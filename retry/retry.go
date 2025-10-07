// Package retry provides an http.RoundTripper middleware for automatically
// retrying failed HTTP requests. It allows fine-grained control over retry
// logic using a customizable Policy and a backoff.Strategy for delays
// between attempts.
//
// The core of the package is NewTransport, which wraps an existing
// http.RoundTripper (like http.DefaultTransport) and intercepts requests to
// apply the retry logic.
//
// Example:
//
//	func main() {
//	  // Create a retry transport that wraps the default transport.
//	  // It will retry up to 3 times with an exponential backoff of 1s to 1m.
//	  transport := retry.NewTransport(
//	    http.DefaultTransport,
//	    retry.WithAttemptLimit(3),
//	    retry.WithBackoff(backoff.New(
//	      backoff.WithMinDelay(1*time.Second),
//	      backoff.WithMaxDelay(1*time.Minute),
//	    )),
//	  )
//
//	  // Create an http.Client that uses our custom transport.
//	  client := &http.Client{
//	    Transport: transport,
//	  }
//
//	  // Make a request using the client. If the request fails with a
//	  // temporary or transient error, it will be automatically retried.
//	  res, err := client.Get("http://example.com/some-flaky-endpoint")
//	  if err != nil {
//	    slog.Error("Request failed after all retries", "error", err)
//	  }
//	  defer res.Body.Close()
//
//	  slog.Info("Request succeeded with status", "status", res.Status)
//	}
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

// Attempt holds the context for a single HTTP request attempt. It captures the
// request, response, error, and the attempt count, providing all necessary
// information for a Policy to make a retry decision.
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

// Transient reports whether the error is a network-level issue that might be
// resolved on a subsequent attempt. This includes network timeouts and
// unexpected EOF errors. It explicitly returns false for context cancellations,
// which should not be retried.
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

// Policy is a function that decides whether a failed request attempt should
// be retried. It receives the Attempt details and returns true to schedule a
// retry, or false to stop.
type Policy func(a Attempt) bool

// LimitAttempts returns a new Policy that wraps the original and adds a
// maximum attempt limit. Retries will only be considered if the attempt count
// is less than n AND the wrapped policy also returns true.
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
			break // Success or policy decided to exit
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

// NewTransport creates and returns a new retrying http.RoundTripper. It wraps
// an existing transport and retries requests based on the configured policy
// and backoff strategy.
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

// WithAttemptLimit sets the maximum number of attempts for a request. A value
// of 0 or less means no limit is enforced besides the policy itself.
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
