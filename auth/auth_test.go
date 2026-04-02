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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/deep-rent/nexus/auth"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/router"
)

type mockVerifier[T jwt.Claims] struct {
	verifyFn func(in []byte) (T, error)
}

func (m *mockVerifier[T]) Verify(in []byte) (T, error) {
	return m.verifyFn(in)
}

var _ jwt.Verifier[jwt.Claims] = (*mockVerifier[jwt.Claims])(nil)

func TestClaims_HasRole(t *testing.T) {
	t.Parallel()
	c := &auth.Claims{Roles: []string{"admin", "editor"}}

	assert.True(t, c.HasRole("admin"))
	assert.False(t, c.HasRole("viewer"))
}

func TestRules(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c := &auth.Claims{Roles: []string{"manager"}}

	t.Run("HasRole", func(t *testing.T) {
		var rule auth.Rule[*auth.Claims]

		rule = auth.HasRole[*auth.Claims]("manager")
		assert.NoError(t, rule.Eval(ctx, c))

		rule = auth.HasRole[*auth.Claims]("admin")
		assert.Error(t, rule.Eval(ctx, c))
	})

	t.Run("AnyRole", func(t *testing.T) {
		var rule auth.Rule[*auth.Claims]

		rule = auth.AnyRole[*auth.Claims]("admin", "manager")
		assert.NoError(t, rule.Eval(ctx, c))

		rule = auth.AnyRole[*auth.Claims]("admin", "user")
		assert.Error(t, rule.Eval(ctx, c))
	})

	t.Run("AllRoles", func(t *testing.T) {
		var rule auth.Rule[*auth.Claims]

		rule = auth.AllRoles[*auth.Claims]("manager")
		assert.NoError(t, rule.Eval(ctx, c))

		rule = auth.AllRoles[*auth.Claims]("manager", "admin")
		assert.Error(t, rule.Eval(ctx, c))
	})
}

func TestGuard_Secure(t *testing.T) {
	t.Parallel()

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
			rules:      []auth.Rule[*auth.Claims]{auth.HasRole[*auth.Claims]("admin")},
			wantStatus: http.StatusForbidden,
			wantReason: auth.ReasonInsufficientPrivileges,
		},
		{
			name:       "success",
			token:      "Bearer valid",
			rules:      []auth.Rule[*auth.Claims]{auth.HasRole[*auth.Claims]("user")},
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mv := &mockVerifier[*auth.Claims]{
				verifyFn: func(in []byte) (*auth.Claims, error) {
					if tc.mockErr != nil {
						return nil, tc.mockErr
					}
					return &auth.Claims{Roles: []string{"user"}}, nil
				},
			}

			guard := auth.NewGuard(mv)
			handler := guard.Secure(tc.rules...)(
				router.HandlerFunc(func(e *router.Exchange) error {
					e.Status(http.StatusOK)
					return nil
				}),
			)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.token != "" {
				req.Header.Set("Authorization", tc.token)
			}

			rec := httptest.NewRecorder()
			e := &router.Exchange{R: req, W: router.NewResponseWriter(rec)}

			err := handler.ServeHTTP(e)

			if tc.wantStatus == http.StatusOK {
				assert.NoError(t, err)
				assert.Equal(t, http.StatusOK, rec.Code)
			} else {
				var re *router.Error
				require.True(t, errors.As(err, &re))
				assert.Equal(t, tc.wantStatus, re.Status)
				assert.Equal(t, tc.wantReason, re.Reason)
			}
		})
	}
}

func TestContextExtraction(t *testing.T) {
	t.Parallel()

	expected := &auth.Claims{Roles: []string{"tester"}}
	mv := &mockVerifier[*auth.Claims]{
		verifyFn: func(in []byte) (*auth.Claims, error) {
			return expected, nil
		},
	}

	guard := auth.NewGuard(mv)
	handler := guard.Secure()(router.HandlerFunc(func(e *router.Exchange) error {
		claims, ok := auth.From[*auth.Claims](e)
		assert.True(t, ok)
		assert.Equal(t, expected, claims)

		e.Status(http.StatusOK)
		return nil
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer valid")
	res := router.NewResponseWriter(httptest.NewRecorder())
	e := &router.Exchange{R: req, W: res}

	err := handler.ServeHTTP(e)
	assert.NoError(t, err)
}
