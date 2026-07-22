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

package token

import (
	"context"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/deep-rent/nexus/sys/schedule"
)

// DefaultBufferTime is the default duration to preemptively refresh tokens.
const DefaultBufferTime = 1 * time.Minute

// RetryDelay is the time to wait before retrying a failed fetch.
// Only used when a scheduler is provided.
const RetryDelay = 5 * time.Second

// Fetcher is a function that generates or retrieves a new token and its exact
// expiration time. It is called by the [Source] when a token is missing or
// expired.
//
// A single fetch is shared by all concurrent [Source.Get] calls, so the
// context passed to a Fetcher is detached from any individual caller's
// cancellation. A Fetcher that performs a network call should therefore bound
// its own duration, for example through the timeout of its HTTP client, rather
// than relying on the caller to cancel it.
type Fetcher func(ctx context.Context) (string, time.Time, error)

// config defines the configuration options for a [Source].
type config struct {
	buf   time.Duration
	now   func() time.Time
	sched schedule.Scheduler
}

// Option modifies the token cache configuration.
type Option func(*config)

// WithBufferTime sets a custom buffer time for proactive token refreshing.
// If not specified or nonpositive, [DefaultBufferTime] is used.
func WithBufferTime(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.buf = d
		}
	}
}

// WithClock injects a custom clock function, primarily used for testing.
// If not provided, [time.Now] is used; nil values will be ignored.
func WithClock(now func() time.Time) Option {
	return func(c *config) {
		if now != nil {
			c.now = now
		}
	}
}

// WithScheduler configures the Source to eagerly fetch and proactively refresh
// tokens in the background using the provided scheduler. If not provided,
// tokens are refreshed synchronously during the [Source.Get] call.
func WithScheduler(sched schedule.Scheduler) Option {
	return func(c *config) {
		c.sched = sched
	}
}

// Source manages a lazy-loaded, automatically refreshing token cache.
// It is safe for concurrent use by multiple goroutines.
type Source struct {
	fetch Fetcher
	buf   time.Duration
	now   func() time.Time

	mu  sync.RWMutex
	tok string
	exp time.Time

	grp singleflight.Group
}

// NewSource creates a new token cache around the given [Fetcher].
func NewSource(fetch Fetcher, opts ...Option) *Source {
	cfg := config{
		buf: DefaultBufferTime,
		now: time.Now,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	src := &Source{
		fetch: fetch,
		buf:   cfg.buf,
		now:   cfg.now,
	}

	if s := cfg.sched; s != nil {
		s.Dispatch(schedule.TickFn(src.refresh))
	}

	return src
}

// Get returns the current valid token, or fetches a new one if it is missing or
// within the expiration buffer window.
func (s *Source) Get(ctx context.Context) (string, error) {
	s.mu.RLock()
	// Consider the token expired if we are within the buffer window.
	if s.tok != "" && s.now().Add(s.buf).Before(s.exp) {
		tok := s.tok
		s.mu.RUnlock()
		return tok, nil
	}
	s.mu.RUnlock()

	return s.get(ctx)
}

// get fetches the token, collapsing concurrent calls into one fetch via the
// singleflight group. The caller may still abandon the wait through its own
// context; the fetch itself continues, since its result is shared and cached.
func (s *Source) get(ctx context.Context) (string, error) {
	ch := s.grp.DoChan("fetch", func() (any, error) {
		// Detach from the caller's context. The fetch is shared by every
		// concurrent Get, so one caller cancelling must not fail it for the
		// others; only cancellation is dropped, so trace and other values on
		// the winning caller's context are preserved. The fetcher is expected
		// to bound its own duration.
		tok, exp, err := s.fetch(context.WithoutCancel(ctx))
		if err != nil {
			return "", err
		}

		s.mu.Lock()
		s.tok = tok
		s.exp = exp
		s.mu.Unlock()

		return tok, nil
	})

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return "", res.Err
		}
		return res.Val.(string), nil
	}
}

// refresh is a background job that periodically fetches the token just before
// it expires.
func (s *Source) refresh(ctx context.Context) time.Duration {
	s.mu.RLock()
	exp := s.exp
	s.mu.RUnlock()

	now := s.now()
	refreshAt := exp.Add(-s.buf)

	if exp.IsZero() || !now.Before(refreshAt) {
		_, err := s.get(ctx)
		if err != nil {
			// On error, wait a short backoff before retrying.
			return RetryDelay
		}
		// Trigger immediately to recalculate wait time based on the new
		// expiration time.
		return 0
	}

	return refreshAt.Sub(now)
}
