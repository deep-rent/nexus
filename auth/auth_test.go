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
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
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
		t.Errorf("for role %q: got %t; want %t", wantRoleA, false, true)
	}

	wantRoleC := "c"
	if c.HasRole(wantRoleC) {
		t.Errorf("for role %q: got %t; want %t", wantRoleC, true, false)
	}
}

func TestClaims_Memberships(t *testing.T) {
	t.Parallel()

	teams := []string{"team-a", "team-b"}
	c := &auth.Claims{Teams: teams}

	got := c.Memberships()
	if len(got) != len(teams) {
		t.Fatalf("got %d memberships; want %d", len(got), len(teams))
	}
	for i, team := range teams {
		if got[i] != team {
			t.Errorf("at index %d: got %q; want %q", i, got[i], team)
		}
	}

	if got := (&auth.Claims{}).Memberships(); len(got) != 0 {
		t.Errorf("without teams: got %v; want none", got)
	}
}

func TestScope(t *testing.T) {
	t.Parallel()

	t.Run("unmarshal string", func(t *testing.T) {
		var s auth.Scope
		if err := json.Unmarshal([]byte(`"read write"`), &s); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(s, auth.Scope{"read", "write"}) {
			t.Errorf("got %v; want [read write]", s)
		}
	})

	t.Run("marshal", func(t *testing.T) {
		s := auth.Scope{"read", "write"}
		got, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		if want := `"read write"`; string(got) != want {
			t.Errorf("got %s; want %s", got, want)
		}
	})

	t.Run("string representation", func(t *testing.T) {
		s := auth.Scope{"read", "write"}
		if got, want := s.String(), "read write"; got != want {
			t.Errorf("got %q; want %q", got, want)
		}
	})
}

func TestClaims_HasScope(t *testing.T) {
	t.Parallel()
	c := &auth.Claims{Scope: auth.Scope{"read", "write"}}

	if !c.HasScope("read") {
		t.Errorf("for scope %q: got false; want true", "read")
	}
	if c.HasScope("delete") {
		t.Errorf("for scope %q: got true; want false", "delete")
	}
}

func TestClaims_Delegated(t *testing.T) {
	t.Parallel()

	c1 := &auth.Claims{}
	if c1.Delegated() {
		t.Error("for empty claims: got true; want false")
	}

	c2 := &auth.Claims{Azp: "client1"}
	c2.Sub = "client1"
	if c2.Delegated() {
		t.Error("when azp equals sub: got true; want false")
	}

	c3 := &auth.Claims{Azp: "client1"}
	c3.Sub = "user1"
	if !c3.Delegated() {
		t.Error("when azp differs from sub: got false; want true")
	}
}

func TestRules(t *testing.T) {
	t.Parallel()
	c := &auth.Claims{Roles: []string{"a", "b"}, Scope: auth.Scope{"read", "write"}}

	tests := []struct {
		name    string
		rule    auth.Rule[*auth.Claims]
		wantErr bool
	}{
		{"HasRole success", auth.HasRole[*auth.Claims]("a"), false},
		{"HasRole failure", auth.HasRole[*auth.Claims]("c"), true},
		{"HasRole multi success", auth.HasRole[*auth.Claims]("a", "b"), false},
		{"HasRole multi failure", auth.HasRole[*auth.Claims]("a", "c"), true},
		{"HasScope success", auth.HasScope[*auth.Claims]("read"), false},
		{"HasScope failure", auth.HasScope[*auth.Claims]("delete"), true},
		{"HasScope multi success", auth.HasScope[*auth.Claims]("read", "write"), false},
		{"HasScope multi failure", auth.HasScope[*auth.Claims]("read", "delete"), true},
		{"Any success", auth.Any(auth.HasRole[*auth.Claims]("c"), auth.HasRole[*auth.Claims]("a")), false},
		{"Any failure", auth.Any(auth.HasRole[*auth.Claims]("c"), auth.HasRole[*auth.Claims]("d")), true},
		{"All success", auth.All(auth.HasRole[*auth.Claims]("a"), auth.HasScope[*auth.Claims]("read")), false},
		{"All failure", auth.All(auth.HasRole[*auth.Claims]("a"), auth.HasScope[*auth.Claims]("delete")), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.rule.Eval(t.Context(), c)
			if tt.wantErr {
				if err == nil {
					t.Error("should have returned an error")
				}
			} else {
				if err != nil {
					t.Errorf("should not have returned an error: %v", err)
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
					t.Errorf("should not have returned an error: %v", err)
				}
				if rec.Code != tt.wantStatus {
					t.Errorf(
						"status code: got %d; want %d", rec.Code, tt.wantStatus,
					)
				}
			} else {
				var re *router.Error
				if !errors.As(err, &re) {
					t.Fatalf(
						"got error %v; want type *router.Error", err,
					)
				}
				if re.Status != tt.wantStatus {
					t.Errorf(
						"status code: got %d; want %d",
						re.Status,
						tt.wantStatus,
					)
				}
				if re.Reason != tt.wantReason {
					t.Errorf(
						"reason: got %q; want %q",
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
				"from exchange: got ok %t; want %t", ok1, true,
			)
		}
		if c1 != want {
			t.Errorf(
				"from exchange: got claims %v; want %v", c1, want,
			)
		}

		c2, ok2 := auth.FromRequest[*auth.Claims](e.R)
		if !ok2 {
			t.Errorf(
				"from request: got ok %t; want %t", ok2, true,
			)
		}
		if c2 != want {
			t.Errorf(
				"from request: got claims %v; want %v", c2, want,
			)
		}

		c3, ok3 := auth.FromContext[*auth.Claims](e.Context())
		if !ok3 {
			t.Errorf(
				"from context: got ok %t; want %t", ok3, true,
			)
		}
		if c3 != want {
			t.Errorf(
				"from context: got claims %v; want %v", c3, want,
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
		t.Errorf("should not have returned an error: %v", err)
	}
}

func TestGuard_CustomExtractor(t *testing.T) {
	t.Parallel()

	v := &mockVerifier[*auth.Claims]{
		verify: func(in []byte) (*auth.Claims, error) {
			if string(in) == "custom-token" {
				return &auth.Claims{Roles: []string{"tester"}}, nil
			}
			return nil, errors.New("invalid token")
		},
	}

	customExt := func(r *http.Request) string {
		return r.URL.Query().Get("token")
	}

	guard := auth.NewGuard(v, customExt)
	handler := guard.Secure()(router.HandlerFunc(func(e *router.Exchange) error {
		e.Status(http.StatusOK)
		return nil
	}))

	req := httptest.NewRequest(http.MethodGet, "/?token=custom-token", nil)
	rec := httptest.NewRecorder()
	e := &router.Exchange{R: req, W: router.NewResponseWriter(rec)}

	if err := handler.ServeHTTP(e); err != nil {
		t.Errorf("should not have returned an error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status code: got %d; want %d", rec.Code, http.StatusOK)
	}
}
