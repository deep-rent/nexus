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

// Package check provides a collection of standard health check constructors for
// common infrastructure dependencies.
//
// It includes implementations for TCP connectivity, HTTP responsiveness, DNS
// resolution, and database pings. These functions return a [health.CheckFunc]
// that can be registered with a [health.Monitor] to automate dependency
// monitoring.
//
// # Usage
//
// The constructors in this package are designed to be passed directly into the
// Attach method of a [health.Monitor].
//
// Example:
//
//	monitor := health.NewMonitor()
//
//	// Check a Redis instance via TCP
//	monitor.Attach(
//		"redis",
//		2*time.Second,
//		check.TCP("localhost:6379", 1*time.Second),
//	)
//
//	// Check an external API with a custom HTTP client
//	monitor.Attach(
//		"stripe",
//		10*time.Second,
//		check.HTTP("https://api.stripe.com/health", check.WithClient(client)),
//	)
package check
