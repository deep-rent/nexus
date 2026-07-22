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

// Package health provides a registry and HTTP handlers for application health
// monitoring.
//
// It allows for the registration of pluggable health checks with built-in
// TTL-based caching to prevent overloading downstream dependencies. The package
// handles the orchestration of these checks, providing thread-safe execution
// and aggregation of results into standardized [Report] formats suitable for
// automated monitoring systems and human inspection.
//
// # Usage
//
// To use the health monitor, create a new instance, attach your dependency
// checks, and mount the handlers to your router.
//
// Example:
//
//	monitor := health.NewMonitor()
//
//	// Register a check with a 5-second minimum delay between invocations.
//	monitor.Attach("database", 5*time.Second, check.Ping(db))
//
//	// Mount the standard endpoints (/health, /health/live, /health/ready)
//	// to a router.Router instance.
//	monitor.Mount(r)
package health
