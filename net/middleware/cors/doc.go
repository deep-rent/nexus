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

// Package cors provides a configurable CORS middleware for http.Handlers.
//
// It implements Cross-Origin Resource Sharing for [http.Handler] instances:
// preflight (OPTIONS) requests are handled and terminated automatically, and
// the appropriate CORS headers are injected into responses for actual
// requests.
//
// Requests without an Origin header, and requests from origins outside the
// configured whitelist, pass through to the next handler without CORS
// headers; the browser then blocks cross-origin access on the client side.
//
// # Usage
//
// The [New] function creates the middleware pipe, which can be configured with
// functional options (e.g., [WithAllowedOrigins], [WithAllowedMethods]).
//
// Example:
//
//	// Configure CORS to allow requests from a specific origin with
//	// restricted methods and additional headers.
//	pipe := cors.New(
//	  cors.WithAllowedOrigins("https://example.com"),
//	  cors.WithAllowedMethods(http.MethodGet, http.MethodOptions),
//	  cors.WithAllowedHeaders("Authorization", "Content-Type"),
//	  cors.WithMaxAge(12*time.Hour),
//	)
//
//	handler := http.HandlerFunc( ... )
//	// Apply the CORS middleware as one of the first layers.
//	chainedHandler := middleware.Chain(handler, pipe)
//
//	http.ListenAndServe(":8080", chainedHandler)
package cors
