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
