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

// Package auth provides JWT-based authentication and authorization middleware
// for the router ecosystem.
//
// It defines a [Guard] that intercepts incoming requests, extracts and verifies
// a Bearer token, and evaluates a set of authorization rules. Successfully
// parsed claims are injected into the request context for downstream handlers.
//
// # Usage
//
// To secure your API, configure a Guard with a JWT verifier and apply it as
// middleware using the router's chaining capabilities. You can define custom
// rules or use the provided role-based rules.
//
// Example:
//
//	// 1. Initialize the JWT verifier and the auth guard.
//	verifier := jwt.NewVerifier[*auth.Claims](keySet)
//	guard := auth.NewGuard(verifier)
//
//	// 2. Setup the router.
//	r := router.New()
//
//	// 3. Protect a route requiring authentication and specific roles.
//	r.HandleFunc(
//	  "POST /admin/users",
//	  createUser,
//	  guard.Secure(auth.HasRole[*auth.Claims]("admin")),
//	)
//
//	// Inside your handler, retrieve the claims:
//	func createUser(e *router.Exchange) error {
//	  claims, ok := auth.From[*auth.Claims](e)
//	  if !ok {
//	    return errors.New("claims missing")
//	  }
//	  // ... handle request ...
//	}
package auth
