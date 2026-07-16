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
//	fetch := func(ctx context.Context) (string, time.Time, error) {
//		// Generate or fetch the token...
//		return "token_string", time.Now().Add(1 * time.Hour), nil
//	}
//
//	// Create a source that refreshes tokens 5 minutes before expiration.
//	source := token.NewSource(fetch, 5*time.Minute)
//
//	// Retrieve the token. The fetcher is called only if the cached token is
//	// missing or expired (within the buffer window).
//	tok, err := source.Get(ctx)
package token

import (
	"context"
	"sync"
	"time"
)

// Fetcher is a function that generates or retrieves a new token and its exact
// expiration time. It is called by the [Source] when a token is missing or
// expired.
type Fetcher func(ctx context.Context) (string, time.Time, error)

// Source manages a lazy-loaded, automatically refreshing token cache.
// It is safe for concurrent use by multiple goroutines.
type Source struct {
	fetch  Fetcher
	buffer time.Duration

	mu  sync.Mutex
	tok string
	exp time.Time
}

// NewSource creates a new token cache. The provided buffer duration is
// subtracted from the token's actual expiration time to proactively trigger a
// refresh before the token is rejected by the server.
func NewSource(fetch Fetcher, buffer time.Duration) *Source {
	return &Source{
		fetch:  fetch,
		buffer: buffer,
	}
}

// Get returns the current valid token, or fetches a new one if it is missing or
// within the expiration buffer window.
func (s *Source) Get(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Consider the token expired if we are within the buffer window.
	if s.tok != "" && time.Now().Add(s.buffer).Before(s.exp) {
		return s.tok, nil
	}

	tok, exp, err := s.fetch(ctx)
	if err != nil {
		return "", err
	}

	s.tok = tok
	s.exp = exp

	return s.tok, nil
}
