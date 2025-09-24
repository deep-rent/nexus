package retry

import (
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/deep-rent/nexus/backoff"
)

type Policy func(resp *http.Response, err error, attempt int) bool

type config struct {
	policy  Policy
	backoff backoff.Strategy
}

type Option func(*config)

func WithPolicy(policy Policy) Option {
	return func(c *config) {
		if policy != nil {
			c.policy = policy
		}
	}
}

func WithBackoff(strategy backoff.Strategy) Option {
	return func(c *config) {
		if strategy != nil {
			c.backoff = strategy
		}
	}
}

type roundTripper struct {
	next    http.RoundTripper
	policy  Policy
	backoff backoff.Strategy
}

func NewTransport(
	next http.RoundTripper,
	opts ...Option,
) http.RoundTripper {
	c := config{
		policy: func(_ *http.Response, err error, _ int) bool {
			return err != nil
		},
		backoff: backoff.Constant(0),
	}
	for _, opt := range opts {
		opt(&c)
	}
	return &roundTripper{
		next:    next,
		policy:  c.policy,
		backoff: c.backoff,
	}
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	var (
		res     *http.Response
		err     error
		attempt int
	)

	defer rt.backoff.Done()

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

		res, err = rt.next.RoundTrip(req)

		// If the request body is not rewindable, we cannot retry
		if req.Body != nil && !rewindable {
			break
		}

		// Ask the policy if we should retry
		if !rt.policy(res, err, attempt) {
			break // Success or policy decided to stop
		}

		// If retrying, drain and close the previous response body
		if res != nil && res.Body != nil {
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
		}

		delay := rt.backoff.Next()
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

func Limit(limit int, next Policy) Policy {
	return func(res *http.Response, err error, attempt int) bool {
		return attempt < limit && next(res, err, attempt)
	}
}

func OnStatus(codes ...int) Policy {
	return func(res *http.Response, err error, _ int) bool {
		return res != nil && err == nil && slices.Contains(codes, res.StatusCode)
	}
}

func OnErrors(filter func(error) bool) Policy {
	return func(_ *http.Response, err error, _ int) bool {
		return err != nil && filter(err)
	}
}

func Any(policies ...Policy) Policy {
	return func(res *http.Response, err error, attempt int) bool {
		for _, policy := range policies {
			if policy(res, err, attempt) {
				return true
			}
		}
		return false
	}
}
