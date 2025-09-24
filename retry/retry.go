package retry

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/deep-rent/nexus/backoff"
	"github.com/deep-rent/nexus/header"
)

type Attempt struct {
	Request  *http.Request
	Response *http.Response
	Err      error
	Number   int
}

func (a Attempt) Idempotent() bool {
	return Idempotent(a.Request.Method)
}

func (a Attempt) Temporary() bool {
	return a.Response != nil && Temporary(a.Response.StatusCode)
}

func (a Attempt) Transient() bool {
	return Transient(a.Err)
}

type Policy func(a Attempt) bool

func DefaultPolicy() Policy {
	return func(a Attempt) bool {
		return a.Idempotent() && (a.Temporary() || a.Transient())
	}
}

func LimitAttempts(n int, next Policy) Policy {
	if n <= 0 {
		return next
	}
	return func(a Attempt) bool {
		return a.Number < n && next(a)
	}
}

type config struct {
	policy  Policy
	limit   int
	backoff backoff.Strategy
	clock   func() time.Time
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

func WithClock(now func() time.Time) Option {
	return func(c *config) {
		if now != nil {
			c.clock = now
		}
	}
}

type transport struct {
	next    http.RoundTripper
	policy  Policy
	backoff backoff.Strategy
	clock   func() time.Time
}

func NewTransport(
	next http.RoundTripper,
	opts ...Option,
) http.RoundTripper {
	c := config{
		policy:  DefaultPolicy(),
		limit:   0,
		backoff: backoff.Constant(0),
	}
	for _, opt := range opts {
		opt(&c)
	}
	return &transport{
		next:    next,
		policy:  LimitAttempts(c.limit, c.policy),
		backoff: c.backoff,
		clock:   c.clock,
	}
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	var (
		res     *http.Response
		err     error
		attempt int
	)

	defer t.backoff.Done()

	rewindable := req.GetBody != nil
	for {
		attempt++

		// If this is a retry and the body is rewindable, obtain a new reader
		if attempt > 1 && rewindable {
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
			Err:      err,
			Number:   attempt,
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
			if d := header.Throttle(res.Header, t.clock); d != 0 {
				// Use the longer of the two delays to respect both the server
				// and our own backoff policy
				delay = max(delay, d)
			}
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

func Idempotent(method string) bool {
	switch method {
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

func Transient(err error) bool {
	if err == nil ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var e net.Error
	if errors.As(err, &e) {
		if e.Timeout() {
			return true
		}
	}

	return errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)
}

func Temporary(code int) bool {
	switch code {
	case
		http.StatusRequestTimeout,      // 408
		http.StatusTooManyRequests,     // 429
		http.StatusInternalServerError, // 500
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable,  // 503
		http.StatusGatewayTimeout:      // 504
		return true
	default:
		return false
	}
}
