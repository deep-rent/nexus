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

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/deep-rent/nexus/header"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/router"
)

// Scheme defines the expected authentication scheme for the Authorization
// header. It is used to extract the JWT token from the request.
const Scheme = "Bearer"

const (
	// ReasonAuthenticationFailed serves as a generic fallback for identity
	// verification errors that do not map to a more specific reason.
	ReasonAuthenticationFailed = "authentication_failed"
	// ReasonMissingToken indicates that the Authorization header was either
	// missing or did not contain a valid Bearer token.
	ReasonMissingToken = "missing_token"
	// ReasonInvalidToken indicates a token was provided but is unusable,
	// typically due to expiration, a malformed structure, or a signature
	// mismatch.
	ReasonInvalidToken = "invalid_token"
	// ReasonInsufficientPrivileges indicates the user is authenticated, but
	// their assigned scopes or roles do not permit access to the resource.
	ReasonInsufficientPrivileges = "insufficient_privileges"
)

const (
	// RoleAdmin represents an elevated user role with full administrative
	// access.
	RoleAdmin = "admin"
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

// Must retrieves the parsed claims from a [*router.Exchange].
// It panics if the claims are not present in the exchange. This is useful
// when the route is guaranteed to have claims injected by middleware.
func Must[T jwt.Claims](e *router.Exchange) T {
	claims, ok := From[T](e)
	if !ok {
		panic("claims missing from exchange")
	}
	return claims
}

// AccessClaims defines an interface for JWT claims that support role-based,
// scope-based, and team-based access control checks.
type AccessClaims interface {
	jwt.Claims
	// HasRole checks if the provided role exists within the claims.
	HasRole(name string) bool
	// HasScope checks if the provided scope exists within the claims.
	HasScope(name string) bool
	// Memberships returns the identifiers of all teams the subject belongs
	// to, taken from the "teams" claim.
	Memberships() []string
	// Delegated reports whether the token was issued to a client acting on
	// behalf of an end user rather than to the client itself.
	Delegated() bool
}

// Scope represents the "scope" claim of a JWT as defined in RFC 6749.
// It is stored as a space-delimited string in JSON but handled as a slice
// internally to optimize lookup performance.
type Scope []string

// UnmarshalJSON handles the parsing of the space-delimited scope string.
func (s *Scope) UnmarshalJSON(b []byte) error {
	var raw string
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*s = strings.Fields(raw)
	return nil
}

// MarshalJSON joins the scopes back into a space-delimited string.
func (s Scope) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// String returns the space-delimited string representation.
func (s Scope) String() string {
	return strings.Join(s, " ")
}

// Claims is a standard implementation of [AccessClaims]. It embeds the standard
// JWT reserved claims and adds additional claims for roles and scopes.
type Claims struct {
	jwt.Reserved
	// Azp represents the authorized party to which the token was issued.
	// It typically identifies the client application.
	Azp string `json:"azp,omitempty"`
	// Roles represents the application-specific roles assigned to the subject,
	// used for Role-Based Access Control (RBAC).
	Roles []string `json:"roles,omitempty"`
	// Scope represents the set of granted OAuth2/OIDC scopes as defined in
	// RFC 6749, typically used for delegated authorization.
	Scope Scope `json:"scope,omitempty"`
	// Teams lists the identifiers of all teams the subject is a member of.
	Teams []string `json:"teams,omitempty"`
}

// HasRole implements the [AccessClaims] interface.
func (c *Claims) HasRole(name string) bool {
	return slices.Contains(c.Roles, name)
}

// HasScope implements the [AccessClaims] interface.
func (c *Claims) HasScope(name string) bool {
	return slices.Contains(c.Scope, name)
}

// Memberships implements the [AccessClaims] interface.
func (c *Claims) Memberships() []string {
	return c.Teams
}

// Delegated returns true if the token was issued to an authorized party (azp)
// that is different from the subject (sub).
//
// This is useful for distinguishing between a client acting on its own behalf
// (machine-to-machine) and a client acting on behalf of a user (delegation).
func (c *Claims) Delegated() bool {
	return c.Azp != "" && c.Azp != c.Sub
}

var _ AccessClaims = (*Claims)(nil)

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

// Eval calls f(ctx, claims) to implement the [Rule] interface.
func (f RuleFunc[T]) Eval(ctx context.Context, claims T) error {
	return f(ctx, claims)
}

// All creates a [Rule] that passes only if all the provided rules pass (AND).
// It returns the error from the first rule that fails.
func All[T jwt.Claims](rules ...Rule[T]) Rule[T] {
	return RuleFunc[T](func(ctx context.Context, claims T) error {
		for _, r := range rules {
			if err := r.Eval(ctx, claims); err != nil {
				return err
			}
		}
		return nil
	})
}

// Any creates a [Rule] that passes if at least one of the provided rules
// passes (OR). If all rules fail, it returns an error combining the reasons.
func Any[T jwt.Claims](rules ...Rule[T]) Rule[T] {
	return RuleFunc[T](func(ctx context.Context, claims T) error {
		var errs []error
		for _, r := range rules {
			if err := r.Eval(ctx, claims); err == nil {
				return nil
			} else {
				errs = append(errs, err)
			}
		}
		if len(errs) > 0 {
			return fmt.Errorf("all rules failed: %v", errs)
		}
		return nil
	})
}

// HasRole creates a [Rule] that mandates the presence of all specified roles.
func HasRole[T AccessClaims](roles ...string) Rule[T] {
	return RuleFunc[T](func(ctx context.Context, claims T) error {
		for _, role := range roles {
			if !claims.HasRole(role) {
				return fmt.Errorf("requires role %q", role)
			}
		}
		return nil
	})
}

// HasScope creates a [Rule] that mandates the presence of all specified scopes.
func HasScope[T AccessClaims](scopes ...string) Rule[T] {
	return RuleFunc[T](func(ctx context.Context, claims T) error {
		for _, scope := range scopes {
			if !claims.HasScope(scope) {
				return fmt.Errorf("requires scope %q", scope)
			}
		}
		return nil
	})
}

// Extractor defines a function signature for extracting a token from an HTTP
// request. It returns the extracted token string, or an empty string if no
// token was found.
type Extractor func(r *http.Request) string

// BearerExtractor is the default [Extractor] that attempts to retrieve a token
// from the Authorization header using the Bearer scheme.
func BearerExtractor(r *http.Request) string {
	return header.Credentials(r.Header, Scheme)
}

// Guard is responsible for intercepting HTTP requests, validating their JWT
// authentication, and enforcing defined authorization rules.
type Guard[T jwt.Claims] struct {
	verifier   jwt.Verifier[T]
	extractors []Extractor
}

// NewGuard creates a new [Guard] using the provided JWT verifier and optional
// extractors. If no extractors are provided, it defaults to using
// [BearerExtractor].
func NewGuard[T jwt.Claims](
	v jwt.Verifier[T],
	extractors ...Extractor,
) *Guard[T] {
	if len(extractors) == 0 {
		extractors = []Extractor{BearerExtractor}
	}
	return &Guard[T]{
		verifier:   v,
		extractors: extractors,
	}
}

// Secure produces a [router.Middleware] that protects routes.
//
// It extracts a token using the configured extractors, verifies its signature
// and validity, and ensures all provided rules pass. If any step fails, it
// returns a structured [*router.Error] and halts the middleware chain.
//
// If no rules are provided, Secure acts strictly as an authentication check,
// verifying the token's validity without enforcing any specific authorization
// constraints.
func (g *Guard[T]) Secure(rules ...Rule[T]) router.Middleware {
	return func(next router.Handler) router.Handler {
		return router.HandlerFunc(func(e *router.Exchange) error {
			var token string
			for _, ext := range g.extractors {
				if t := ext(e.R); t != "" {
					token = t
					break
				}
			}

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
					// If a rule explicitly returns an API error, pass it
					// through to allow custom error responses.
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
			e.R = e.R.WithContext(
				context.WithValue(e.Context(), claimsKey, claims),
			)

			return next.ServeHTTP(e)
		})
	}
}
