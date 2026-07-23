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

// Package middleware provides a standard approach for HTTP transport
// middleware.
//
// It offers primitives for chaining and composing HTTP transport middleware,
// focusing on low-level HTTP operations (like logging, CORS, and compression)
// that operate directly on [http.Handler].
//
// For higher-level business logic that requires structured error handling and
// API contexts, see the Middleware definitions in the router package. The
// router provides an adapter to seamlessly integrate the transport pipes
// defined here within its richer handler ecosystem.
//
// # Usage
//
// The core type is [Pipe], an adapter that wraps an [http.Handler] to add
// functionality. The [Chain] function composes these pipes into a single
// handler.
//
// Example:
//
//	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//	  w.Write([]byte("OK"))
//	})
//
//	// Chain middleware around the final handler.
//	// Order matters: Recover must be first (outermost).
//	logger := log.New()
//	chainedHandler := middleware.Chain(handler,
//	  middleware.Recover(logger),
//	  middleware.RequestID(),
//	  middleware.Log(logger),
//	)
//
//	http.ListenAndServe(":8080", chainedHandler)
package middleware
