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

// Package oom provides a middleware to protect the application from
// out-of-memory crashes.
//
// It samples the application's memory usage inline as requests arrive, at most
// once per configured interval, and sheds load by rejecting incoming HTTP
// requests when the usage approaches the configured GOMEMLIMIT. This allows the
// Go garbage collector time to recover and prevents the process from being
// terminated by the operating system.
//
// # Usage
//
// Mount the middleware globally in your router chain. It will automatically
// detect the GOMEMLIMIT environment variable (or runtime setting). If no
// limit is set, the middleware acts as a no-op.
//
//	r := router.New(
//		router.WithMiddleware(oom.Middleware()),
//	)
package oom
