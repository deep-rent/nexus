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
// It defines a Guard that intercepts incoming requests, extracts and verifies
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
//	verifier := jwt.NewVerifier[auth.Claims](keySet)
//	guard := auth.NewGuard(verifier)
//
//	// 2. Setup the router.
//	r := router.New()
//
//	// 3. Protect a route requiring authentication and specific roles.
//	r.HandleFunc(
//		"POST /admin/users",
//		createUserHandler,
//		guard.Secure(auth.HasRole[auth.Claims]("admin")),
//	)
//
//	// Inside your handler, retrieve the claims:
//	func createUserHandler(e *router.Exchange) error {
//		claims, ok := auth.FromExchange[auth.Claims](e)
//		if !ok {
//			return errors.New("claims missing")
//		}
//		// ... handle request ...
//	}
package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/deep-rent/nexus/header"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/router"
)

// Scheme defines the expected authentication scheme for the Authorization
// header. It is used to extract the JWT token from the request.
const Scheme = "Bearer"

const (
	// ReasonMissingToken indicates that the Authorization header was either
	// missing or did not contain a valid Bearer token.
	ReasonMissingToken = "missing_token"
	// ReasonInvalidToken indicates that the token was provided but failed
	// verification (e.g., expired, mismatched signature, or malformed).
	ReasonInvalidToken = "invalid_token"
	// ReasonInsufficientPrivileges indicates that the token is valid, but the
	// associated claims failed to satisfy the required authorization rules.
	ReasonInsufficientPrivileges = "insufficient_privileges"
)

// contextKey prevents collisions with other packages.
type contextKey struct{}

// claimsKey is the internal context key used to store and retrieve parsed
// JWT claims.
var claimsKey contextKey

// FromContext retrieves the parsed claims from a standard [context.Context].
// It returns the claims and a boolean indicating whether they were found.
func FromContext[T jwt.Claims](ctx context.Context) (T, bool) {
	claims, ok := ctx.Value(claimsKey).(T)
	return claims, ok
}

// FromRequest retrieves the parsed claims directly from an [*http.Request].
// It returns the claims and a boolean indicating whether they were found.
func FromRequest[T jwt.Claims](req *http.Request) (T, bool) {
	return FromContext[T](req.Context())
}

// From retrieves the parsed claims from a [*router.Exchange].
// This is the preferred method for extracting claims within route handlers.
func From[T jwt.Claims](e *router.Exchange) (T, bool) {
	return FromContext[T](e.Context())
}

// RoleClaims defines an interface for JWT claims that include role-based
// access control capabilities.
type RoleClaims interface {
	jwt.Claims
	// HasRole checks if the provided role exists within the claims.
	HasRole(name string) bool
}

// Claims is a standard implementation of [RoleClaims]. It embeds the standard
// JWT reserved claims and adds a custom "rol" slice for roles.
type Claims struct {
	jwt.Reserved
	Roles []string `json:"rol,omitempty"`
}

// HasRole returns true if the specified role is present in the Roles slice.
func (c *Claims) HasRole(name string) bool {
	return slices.Contains(c.Roles, name)
}

// Ensure Claims implements RoleClaims.
var _ RoleClaims = (*Claims)(nil)

// Rule defines an authorization condition that must be met for a request to
// proceed. Rules are evaluated after the JWT has been successfully verified.
type Rule[T jwt.Claims] interface {
	// Eval evaluates the rule against the current context and parsed claims.
	// Returning an error indicates the rule failed, and access is denied.
	Eval(ctx context.Context, claims T) error
}

// RuleFunc is an adapter to allow the use of ordinary functions as security
// rules. If f is a function with the appropriate signature, RuleFunc(f) is a
// [Rule] that calls f.
type RuleFunc[T jwt.Claims] func(context.Context, T) error

// Eval calls f(ctx, claims).
func (f RuleFunc[T]) Eval(ctx context.Context, claims T) error {
	return f(ctx, claims)
}

// HasRole creates a Rule that enforces the presence of a specific single role.
func HasRole[T RoleClaims](role string) Rule[T] {
	return RuleFunc[T](func(ctx context.Context, claims T) error {
		if !claims.HasRole(role) {
			return fmt.Errorf("requires role %q", role)
		}
		return nil
	})
}

// AnyRole creates a Rule that passes if the user possesses at least one of the
// specified roles.
func AnyRole[T RoleClaims](roles ...string) Rule[T] {
	return RuleFunc[T](func(ctx context.Context, claims T) error {
		if slices.ContainsFunc(roles, claims.HasRole) {
			return nil
		}
		return fmt.Errorf("requires at least one of the roles: %v", roles)
	})
}

// AllRoles creates a Rule that mandates the presence of all specified roles.
func AllRoles[T RoleClaims](roles ...string) Rule[T] {
	return RuleFunc[T](func(ctx context.Context, claims T) error {
		for _, role := range roles {
			if !claims.HasRole(role) {
				return fmt.Errorf("missing required role %q", role)
			}
		}
		return nil
	})
}

// Guard is responsible for intercepting HTTP requests, validating their JWT
// authentication, and enforcing defined authorization rules.
type Guard[T jwt.Claims] struct {
	verifier *jwt.Verifier[T]
}

// NewGuard creates a new Guard using the provided JWT verifier.
func NewGuard[T jwt.Claims](v *jwt.Verifier[T]) *Guard[T] {
	return &Guard[T]{
		verifier: v,
	}
}

// Secure produces a router Middleware that protects routes.
//
// It extracts a Bearer token from the Authorization header, verifies its
// signature and validity, and ensures all provided rules pass. If any step
// fails, it returns a structured [*router.Error] and halts the middleware
// chain.
func (g *Guard[T]) Secure(rules ...Rule[T]) router.Middleware {
	return func(next router.Handler) router.Handler {
		return router.HandlerFunc(func(e *router.Exchange) error {
			token := header.Credentials(e.R.Header, Scheme)
			if token == "" {
				return &router.Error{
					Status:      http.StatusUnauthorized,
					Reason:      ReasonMissingToken,
					Description: "missing or malformed bearer token",
				}
			}

			claims, err := g.verifier.Verify([]byte(token))
			if err != nil {
				return &router.Error{
					Status:      http.StatusUnauthorized,
					Reason:      ReasonInvalidToken,
					Description: "the provided token is invalid or expired",
					Cause:       err,
				}
			}

			for _, rule := range rules {
				if err := rule.Eval(e.Context(), claims); err != nil {
					// If a rule explicitly returns a router.Error, pass it
					// through to allow custom API error responses.
					if re, ok := errors.AsType[*router.Error](err); ok {
						return re
					}

					// Otherwise, wrap it in a standard 403 Forbidden error.
					return &router.Error{
						Status:      http.StatusForbidden,
						Reason:      ReasonInsufficientPrivileges,
						Description: "access denied by security policy",
						Cause:       err,
					}
				}
			}

			// Embed the verified claims into the request context and update
			// the Exchange so downstream handlers have access.
			e.R = e.R.WithContext(context.WithValue(e.Context(), claimsKey, claims))

			return next.ServeHTTP(e)
		})
	}
}
