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

package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/deep-rent/nexus/auth"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/router"
)

type mockVerifier[T jwt.Claims] struct {
	verify func(in []byte) (T, error)
}

func (m *mockVerifier[T]) Verify(in []byte) (T, error) {
	return m.verify(in)
}

var _ jwt.Verifier[*auth.Claims] = (*mockVerifier[*auth.Claims])(nil)

func TestClaims_HasRole(t *testing.T) {
	t.Parallel()
	c := &auth.Claims{Roles: []string{"a", "b"}}

	wantRoleA := "a"
	if !c.HasRole(wantRoleA) {
		t.Errorf("Claims.HasRole(%q) = %t; want %t", wantRoleA, false, true)
	}

	wantRoleC := "c"
	if c.HasRole(wantRoleC) {
		t.Errorf("Claims.HasRole(%q) = %t; want %t", wantRoleC, true, false)
	}
}

func TestRules(t *testing.T) {
	t.Parallel()
	c := &auth.Claims{Roles: []string{"a", "b"}}

	tests := []struct {
		name    string
		rule    auth.Rule[*auth.Claims]
		wantErr bool
	}{
		{"HasRole success", auth.HasRole[*auth.Claims]("a"), false},
		{"HasRole failure", auth.HasRole[*auth.Claims]("c"), true},
		{"AnyRole success", auth.AnyRole[*auth.Claims]("c", "a"), false},
		{"AnyRole failure", auth.AnyRole[*auth.Claims]("c", "d"), true},
		{"AllRoles success", auth.AllRoles[*auth.Claims]("a", "b"), false},
		{"AllRoles failure", auth.AllRoles[*auth.Claims]("a", "c"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.rule.Eval(t.Context(), c)
			if tt.wantErr {
				if err == nil {
					t.Errorf("rule.Eval() = nil; want error")
				}
			} else {
				if err != nil {
					t.Errorf("rule.Eval() = %v; want nil", err)
				}
			}
		})
	}
}

func TestGuard_Secure(t *testing.T) {
	t.Parallel()

	teapotErr := &router.Error{
		Status: http.StatusTeapot,
		Reason: "teapot",
	}

	tests := []struct {
		name       string
		token      string
		mockErr    error
		rules      []auth.Rule[*auth.Claims]
		wantStatus int
		wantReason string
	}{
		{
			name:       "missing token",
			token:      "",
			wantStatus: http.StatusUnauthorized,
			wantReason: auth.ReasonMissingToken,
		},
		{
			name:       "invalid token",
			token:      "Bearer invalid",
			mockErr:    errors.New("jwt error"),
			wantStatus: http.StatusUnauthorized,
			wantReason: auth.ReasonInvalidToken,
		},
		{
			name:       "insufficient privileges",
			token:      "Bearer valid",
			rules:      []auth.Rule[*auth.Claims]{auth.HasRole[*auth.Claims]("a")},
			wantStatus: http.StatusForbidden,
			wantReason: auth.ReasonInsufficientPrivileges,
		},
		{
			name:  "rule error pass-through",
			token: "Bearer valid",
			rules: []auth.Rule[*auth.Claims]{
				auth.RuleFunc[*auth.Claims](func(context.Context, *auth.Claims) error {
					return teapotErr
				}),
			},
			wantStatus: http.StatusTeapot,
			wantReason: "teapot",
		},
		{
			name:       "success",
			token:      "Bearer valid",
			rules:      []auth.Rule[*auth.Claims]{auth.HasRole[*auth.Claims]("b")},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mv := &mockVerifier[*auth.Claims]{
				verify: func(in []byte) (*auth.Claims, error) {
					if tt.mockErr != nil {
						return nil, tt.mockErr
					}
					return &auth.Claims{Roles: []string{"b"}}, nil
				},
			}

			guard := auth.NewGuard(mv)
			handler := guard.Secure(tt.rules...)(
				router.HandlerFunc(func(e *router.Exchange) error {
					e.Status(http.StatusOK)
					return nil
				}),
			)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", tt.token)
			}

			rec := httptest.NewRecorder()
			e := &router.Exchange{R: req, W: router.NewResponseWriter(rec)}

			err := handler.ServeHTTP(e)

			if tt.wantStatus == http.StatusOK {
				if err != nil {
					t.Errorf("handler.ServeHTTP() = %v; want nil", err)
				}
				if rec.Code != tt.wantStatus {
					t.Errorf("recorder.Code = %d; want %d", rec.Code, tt.wantStatus)
				}
			} else {
				var re *router.Error
				if !errors.As(err, &re) {
					t.Fatalf(
						"handler.ServeHTTP() error = %v; want type *router.Error", err,
					)
				}
				if re.Status != tt.wantStatus {
					t.Errorf(
						"router.Error.Status = %d; want %d",
						re.Status,
						tt.wantStatus,
					)
				}
				if re.Reason != tt.wantReason {
					t.Errorf(
						"router.Error.Reason = %q; want %q",
						re.Reason,
						tt.wantReason,
					)
				}
			}
		})
	}
}

func TestContextExtraction(t *testing.T) {
	t.Parallel()
	want := &auth.Claims{Roles: []string{"tester"}}

	v := &mockVerifier[*auth.Claims]{
		verify: func(in []byte) (*auth.Claims, error) {
			return want, nil
		},
	}

	guard := auth.NewGuard(v)

	handler := guard.Secure()(router.HandlerFunc(func(e *router.Exchange) error {
		c1, ok1 := auth.From[*auth.Claims](e)
		if !ok1 {
			t.Errorf(
				"auth.From(e) ok = %t; want %t", ok1, true,
			)
		}
		if c1 != want {
			t.Errorf(
				"auth.From(e) claims = %v; want %v", c1, want,
			)
		}

		c2, ok2 := auth.FromRequest[*auth.Claims](e.R)
		if !ok2 {
			t.Errorf(
				"auth.FromRequest(e.R) ok = %t; want %t", ok2, true,
			)
		}
		if c2 != want {
			t.Errorf(
				"auth.FromRequest(e.R) claims = %v; want %v", c2, want,
			)
		}

		c3, ok3 := auth.FromContext[*auth.Claims](e.Context())
		if !ok3 {
			t.Errorf(
				"auth.FromContext(e.Context()) ok = %t; want %t", ok3, true,
			)
		}
		if c3 != want {
			t.Errorf(
				"auth.FromContext(e.Context()) claims = %v; want %v", c3, want,
			)
		}

		e.Status(http.StatusOK)
		return nil
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer valid")
	res := router.NewResponseWriter(httptest.NewRecorder())
	e := &router.Exchange{R: req, W: res}

	err := handler.ServeHTTP(e)
	if err != nil {
		t.Errorf("handler.ServeHTTP() = %v; want nil", err)
	}
}
