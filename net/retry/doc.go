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

// Package retry provides an [http.RoundTripper] middleware for automatic,
// policy-driven retries of HTTP requests.
//
// It wraps an existing [http.RoundTripper] (such as [http.DefaultTransport])
// and intercepts requests to apply retry logic. The decision to retry is
// controlled by a [Policy], and the delay between attempts is determined by a
// [backoff.Strategy], which the transport also reconciles with any Retry-After
// or rate-limit headers sent by the server.
//
// Attempts are counted per request, so one transport, policy and backoff
// strategy can serve any number of concurrent requests without their retry
// schedules interfering.
//
// # Usage
//
// A new transport is created with [NewTransport], configured with functional
// options like [WithAttemptLimit] and [WithBackoff].
//
// Example:
//
//	// Retry up to 3 times with exponential backoff starting at 1 second.
//	transport := retry.NewTransport(
//	  http.DefaultTransport,
//	  retry.WithAttemptLimit(3),
//	  retry.WithBackoff(backoff.New(
//	    backoff.WithMinDelay(1*time.Second),
//	  )),
//	)
//
//	client := &http.Client{Timeout: 10 * time.Second, Transport: transport}
//
//	// This request will be retried automatically on temporary failures.
//	res, err := client.Get("http://example.com/flaky")
//	if err != nil {
//	  slog.Error("Request failed after all retries", "error", err)
//	  return
//	}
//	defer res.Body.Close()
//
// Note that the timeout of an [http.Client] covers the entire exchange,
// including every retry and the waiting in between. A timeout shorter than the
// configured backoff leaves no room for retries.
package retry
