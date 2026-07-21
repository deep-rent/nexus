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

// Package jitter provides functionality for adding random variation (jitter) to
// time durations.
//
// This package is designed to help distributed systems avoid "thundering herd"
// problems by desynchronizing retry attempts or periodic jobs. The jitter
// implementation is "subtractive". It calculates a duration randomly chosen
// between [d * (1 - p), d], where p is the jitter percentage. This ensures that
// the returned duration never exceeds the input duration, allowing strict
// adherence to maximum delay limits (e.g., in backoff strategies).
//
// # Usage
//
// Create a [Jitter] instance with a specific percentage and apply it to your
// base durations.
//
// Example:
//
//	// Create a jitterer with 20% randomness.
//	j := jitter.New(0.2, nil)
//
//	// A 10s duration will result in a random value between 8s and 10s.
//	d := j.Apply(10 * time.Second)
package jitter
