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

// Package token provides a reusable, thread-safe, lazy-loading token cache.
// It is designed to cache authentication tokens (like OAuth Access Tokens or
// signed JWTs) and proactively refresh them just before they expire.
//
// # Usage
//
// Create a token [Source] by providing a [Fetcher] function that performs the
// underlying token generation or network fetch, returning the token string and
// its exact expiration time. A buffer duration can be specified to preemptively
// refresh the token before it expires.
//
// Example:
//
//	fetch := func(ctx context.Context) (string, time.Time, error) {
//		// Generate or fetch the token...
//		return "token_string", time.Now().Add(1 * time.Hour), nil
//	}
//
//	// Create a source that refreshes tokens 5 minutes before expiration.
//	source := token.NewSource(fetch, token.WithBufferTime(5*time.Minute))
//
//	// Retrieve the token. The fetcher is called only if the cached token is
//	// missing or expired (within the buffer window).
//	tok, err := source.Get(ctx)
package token

import (
	"context"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// DefaultBufferTime is the default duration to preemptively refresh tokens.
const DefaultBufferTime = 1 * time.Minute

// Fetcher is a function that generates or retrieves a new token and its exact
// expiration time. It is called by the [Source] when a token is missing or
// expired.
type Fetcher func(ctx context.Context) (string, time.Time, error)

// config defines the configuration options for a [Source].
type config struct {
	buf   time.Duration
	clock func() time.Time
}

// Option modifies the token cache configuration.
type Option func(*config)

// WithBufferTime sets a custom buffer time for proactive token refreshing.
// If not specified, DefaultBufferTime is used.
func WithBufferTime(d time.Duration) Option {
	return func(c *config) {
		c.buf = d
	}
}

// WithClock injects a custom clock function, primarily used for testing.
func WithClock(clock func() time.Time) Option {
	return func(c *config) {
		c.clock = clock
	}
}

// Source manages a lazy-loaded, automatically refreshing token cache.
// It is safe for concurrent use by multiple goroutines.
type Source struct {
	fetch Fetcher
	buf   time.Duration
	clock func() time.Time

	mu  sync.RWMutex
	tok string
	exp time.Time

	group singleflight.Group
}

// NewSource creates a new token cache. The provided buffer duration is
// subtracted from the token's actual expiration time to proactively trigger a
// refresh before the token is rejected by the server.
func NewSource(fetch Fetcher, opts ...Option) *Source {
	cfg := config{
		buf:   DefaultBufferTime,
		clock: time.Now,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return &Source{
		fetch: fetch,
		buf:   cfg.buf,
		clock: cfg.clock,
	}
}

// Get returns the current valid token, or fetches a new one if it is missing or
// within the expiration buffer window.
func (s *Source) Get(ctx context.Context) (string, error) {
	s.mu.RLock()
	// Consider the token expired if we are within the buffer window.
	if s.tok != "" && s.clock().Add(s.buf).Before(s.exp) {
		tok := s.tok
		s.mu.RUnlock()
		return tok, nil
	}
	s.mu.RUnlock()

	ch := s.group.DoChan("fetch", func() (interface{}, error) {
		tok, exp, err := s.fetch(ctx)
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
