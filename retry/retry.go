// Copyright (c) 2025-present deep.rent GmbH (https://deep.rent)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package retry

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/deep-rent/nexus/backoff"
	"github.com/deep-rent/nexus/header"
	"github.com/deep-rent/nexus/log"
)

// transport wraps an underlying [http.RoundTripper] to provide automatic
// retries.
type transport struct {
	next    http.RoundTripper // underlying transport used to send requests
	policy  Policy            // decides whether another attempt is made
	backoff backoff.Strategy  // supplies the delay between attempts
	logger  *slog.Logger      // destination for debug output
	now     func() time.Time  // clock used to interpret date headers
	drain   int64             // bytes read from an abandoned response body
}

// NewTransport creates and returns a new retrying [http.RoundTripper].
//
// It wraps an existing transport and retries requests based on the configured
// policy and backoff strategy. Requests that carry a body are only retried if
// that body can be rewound, which is the case when [http.Request.GetBody] is
// set. The helpers in [net/http] set it for the common in-memory body types,
// but not for an arbitrary [io.Reader].
//
// The returned transport is safe for concurrent use if the wrapped transport
// is.
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
		drain:   DefaultMaxDrainBytes,
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
		drain:   cfg.drain,
	}
}

// attemptKey carries the 1-based attempt number in a request context.
type attemptKey struct{}

// AttemptCount reports the 1-based number of the attempt a request is
// currently on, as recorded by the retrying transport in the request context.
// It returns 0 if the request is not executing under a retrying transport.
//
// Transports layered below the retry transport can use this to annotate
// per-attempt work, for example to record a resend count on a trace span.
func AttemptCount(ctx context.Context) int {
	count, _ := ctx.Value(attemptKey{}).(int)
	return count
}

// RoundTrip executes an HTTP transaction, retrying it as directed by the
// configured [Policy].
//
// The caller's request is never modified: retries are sent as clones carrying
// a freshly rewound body. Between attempts, the abandoned response body is
// drained and closed so that the underlying connection can be reused. The
// response handed back to the caller always has its body intact.
//
// The loop honors the request context throughout. If the context carries a
// deadline that would elapse during the next backoff delay, the transport
// stops early and returns the result of the last attempt rather than waiting
// for a cancellation that is certain to happen.
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// A body that cannot be rewound can only be sent once.
	rewindable := req.Body == nil || req.GetBody != nil

	for count := 1; ; count++ {
		actx := context.WithValue(ctx, attemptKey{}, count)

		attempt := req.WithContext(actx)
		if count > 1 {
			var err error
			if attempt, err = rewind(actx, req); err != nil {
				return nil, err
			}
		}

		res, err := t.next.RoundTrip(attempt)

		retry := t.policy(Attempt{
			Request:  attempt,
			Response: res,
			Error:    err,
			Count:    count,
		})

		// The policy is consulted first, so that it observes every attempt
		// even when the request turns out not to be repeatable.
		if !retry || !rewindable {
			if retry {
				t.logger.DebugContext(ctx,
					"Not retrying a request with a non-rewindable body",
					slog.String("method", req.Method),
					slog.String("url", req.URL.String()),
				)
			}
			return res, err
		}

		delay := t.delay(count, res)

		// Waiting past the deadline would turn a usable response into a
		// context error, so the last result is returned while its body is
		// still intact.
		if deadline, ok := ctx.Deadline(); ok &&
			time.Until(deadline) <= delay {
			t.logger.DebugContext(ctx,
				"Not retrying, deadline would elapse during backoff",
				slog.Duration("delay", delay),
				slog.String("method", req.Method),
				slog.String("url", req.URL.String()),
			)
			return res, err
		}

		t.discard(res)
		t.log(ctx, count, delay, req, res, err)

		if err := backoff.Wait(ctx, delay); err != nil {
			return nil, err
		}
	}
}

// rewind clones req for another attempt, obtaining a fresh reader for its
// body. The clone carries the given context, which holds the current attempt
// count. The original request is left untouched, as required by the
// [http.RoundTripper] contract.
func rewind(ctx context.Context, req *http.Request) (*http.Request, error) {
	clone := req.Clone(ctx)
	if req.GetBody == nil {
		return clone, nil
	}

	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	clone.Body = body
	return clone, nil
}

// delay determines how long to wait before the next attempt, reconciling the
// backoff strategy with any throttling hints sent by the server.
func (t *transport) delay(count int, res *http.Response) time.Duration {
	delay := t.backoff.Delay(count)
	if res == nil {
		return delay
	}
	// Use the longer of the two delays to respect both the server's
	// instruction and our own backoff policy.
	return max(delay, header.Throttle(res.Header, t.now))
}

// discard drains and closes the body of an abandoned response, allowing the
// underlying connection to be reused. Reading is bounded: a body that exceeds
// the limit is closed without being consumed, which costs a connection but
// keeps a large error page from stalling the retry loop.
func (t *transport) discard(res *http.Response) {
	if res == nil || res.Body == nil {
		return
	}

	if t.drain > 0 {
		// One byte beyond the limit distinguishes a fully drained body from a
		// truncated one, which must not be reused.
		n, err := io.Copy(io.Discard, io.LimitReader(res.Body, t.drain+1))
		switch {
		case err != nil:
			t.logger.Warn(
				"Failed to drain response body",
				log.Err(err),
			)
		case n > t.drain:
			t.logger.Debug(
				"Abandoned response body exceeds the drain limit",
				slog.Int64("limit", t.drain),
			)
		}
	}

	if err := res.Body.Close(); err != nil {
		t.logger.Warn(
			"Failed to close response body",
			log.Err(err),
		)
	}
}

// log records a failed attempt and the delay preceding the next one.
func (t *transport) log(
	ctx context.Context,
	count int,
	delay time.Duration,
	req *http.Request,
	res *http.Response,
	err error,
) {
	if !t.logger.Enabled(ctx, slog.LevelDebug) {
		return
	}

	attrs := []any{
		slog.Int("attempt", count),
		slog.Duration("delay", delay),
		slog.String("method", req.Method),
		slog.String("url", req.URL.String()),
	}
	if err != nil {
		attrs = append(attrs, log.Err(err))
	}
	if res != nil {
		attrs = append(attrs, slog.Int("status", res.StatusCode))
	}

	t.logger.DebugContext(ctx, "Request attempt failed, retrying", attrs...)
}

var _ http.RoundTripper = (*transport)(nil)
