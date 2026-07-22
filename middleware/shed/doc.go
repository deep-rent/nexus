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

// Package shed provides memory-aware load shedding HTTP middleware.
//
// When an application approaches its memory limit, continuing to accept new
// requests risks Out-Of-Memory (OOM) process termination by the operating
// system. Package shed protects services from OOM crashes by sampling runtime
// memory usage and shedding incoming HTTP load when memory consumption crosses
// a configurable safety threshold. Once memory pressure subsides (e.g.
// following garbage collection), normal request processing resumes
// automatically.
//
// # Usage
//
// Mount the middleware globally in your router chain:
//
//	r := router.New(
//		router.WithMiddleware(shed.New()),
//	)
//
// Customize sampling interval, threshold, and retry timing using functional
// options. The following example sheds load at 85% of the memory limit,
// resamples usage every 100 ms and instructs clients to retry after 10s.
//
//	mw := shed.New(
//		shed.WithThreshold(0.85),
//		shed.WithInterval(100*time.Millisecond),
//		shed.WithRetryAfter(10*time.Second),
//	)
package shed
