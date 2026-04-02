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

package auth

import (
	"context"
	"fmt"
	"net/http"
	"slices"

	"github.com/deep-rent/nexus/header"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/middleware"
)

type Rule[T jwt.Claims] interface {
	Eval(ctx context.Context, claims T) error
}

type RuleFunc[T jwt.Claims] func(context.Context, T) error

func (f RuleFunc[T]) Eval(ctx context.Context, claims T) error {
	return f(ctx, claims)
}

type Guard[T jwt.Claims] struct {
	verifier *jwt.Verifier[T]
}

func NewGuard[T jwt.Claims](v *jwt.Verifier[T]) *Guard[T] {
	return &Guard[T]{
		verifier: v,
	}
}

type contextKey struct{}

var claimsKey contextKey

// FromContext retrieves the parsed claims from the request context.
func FromContext[T jwt.Claims](ctx context.Context) (T, bool) {
	claims, ok := ctx.Value(claimsKey).(T)
	return claims, ok
}

func FromRequest[T jwt.Claims](req *http.Request) (T, bool) {
	return FromContext[T](req.Context())
}

func (g *Guard[T]) Secure(rules ...Rule[T]) middleware.Pipe {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			const Scheme = "Bearer"
			token := header.Credentials(r.Header, Scheme)
			if token == "" {
				http.Error(w, "missing token", http.StatusUnauthorized)
				return
			}
			claims, err := g.verifier.Verify([]byte(token))
			if err != nil {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
			for _, rule := range rules {
				if err := rule.Eval(r.Context(), claims); err != nil {
					http.Error(w, err.Error(), http.StatusForbidden)
					return
				}
			}
			ctx := context.WithValue(r.Context(), claimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type RoleClaims interface {
	jwt.Claims
	HasRole(name string) bool
}

type Claims struct {
	jwt.Reserved
	Roles []string `json:"rol"`
}

func (c *Claims) HasRole(name string) bool {
	return slices.Contains(c.Roles, name)
}

var _ RoleClaims = (*Claims)(nil)

func HasRole[T RoleClaims](role string) Rule[T] {
	return RuleFunc[T](func(ctx context.Context, claims T) error {
		if !claims.HasRole(role) {
			return fmt.Errorf("requires role %q", role)
		}
		return nil
	})
}

func AnyRole[T RoleClaims](roles ...string) Rule[T] {
	return RuleFunc[T](func(ctx context.Context, claims T) error {
		if slices.ContainsFunc(roles, claims.HasRole) {
			return nil // At least one role matches, so the rule passes.
		}
		return fmt.Errorf("requires at least one of the roles: %v", roles)
	})
}
