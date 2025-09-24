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
	clock   func() time.Time
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
			Error:    err,
			Count:    attempt,
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

var _ http.RoundTripper = (*transport)(nil)

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
		policy:  c.policy.LimitAttempts(c.limit),
		backoff: c.backoff,
		clock:   c.clock,
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
