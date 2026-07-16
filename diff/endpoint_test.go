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

package diff_test

import (
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"uuid"

	"github.com/deep-rent/nexus/auth"
	"github.com/deep-rent/nexus/diff"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/router"
)

type mockVerifier struct {
	claims *auth.Claims
}

func (m *mockVerifier) Verify([]byte) (*auth.Claims, error) {
	return m.claims, nil
}

var _ jwt.Verifier[*auth.Claims] = (*mockVerifier)(nil)

// serve mounts the sync endpoint of a fresh fixture behind an auth guard
// that accepts any bearer token as the given claims.
func serve(
	t *testing.T,
	f *fixture,
	claims *auth.Claims,
) *httptest.Server {
	t.Helper()
	r := router.New()
	guard := auth.NewGuard(&mockVerifier{claims: claims})
	diff.Mount[*auth.Claims](r, f.engine, guard.Secure())
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

// claimsFor builds delegated end-user claims for the given user.
func claimsFor(userID string, teams ...string) *auth.Claims {
	c := &auth.Claims{Teams: teams}
	c.Sub = userID
	c.Azp = "test-client" // azp != sub: acting on behalf of the user
	return c
}

// post sends a sync request and returns the status code and decoded body.
func post(
	t *testing.T,
	srv *httptest.Server,
	body string,
) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(
		http.MethodPost, srv.URL+"/sync", strings.NewReader(body))
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer token")

	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	defer func() { _ = res.Body.Close() }()

	var decoded map[string]any
	if err := json.UnmarshalRead(res.Body, &decoded); err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	return res.StatusCode, decoded
}

func TestEndpoint_Sync(t *testing.T) {
	t.Parallel()

	f := setup()
	owner := uuid.NewV7().String()
	srv := serve(t, f, claimsFor(owner))

	doc := assetDoc(uuid.NewV7(), owner, nil)
	code, body := post(t, srv, fmt.Sprintf(
		`{"since":0,"changes":[{"id":%q,"action":"upsert","type":"asset",`+
			`"data":%s,"time":%d}]}`,
		uuid.NewV7(), doc, stamp(1),
	))

	if code != http.StatusOK {
		t.Fatalf("status: got %d; want %d (body %v)",
			code, http.StatusOK, body)
	}
	if _, ok := body["next"]; !ok {
		t.Error("response should carry a next cursor")
	}
	if more, ok := body["more"].(bool); !ok || more {
		t.Errorf("more: got %v; want false", body["more"])
	}
}

func TestEndpoint_Errors(t *testing.T) {
	t.Parallel()

	owner := uuid.NewV7().String()

	valid := func() string {
		return fmt.Sprintf(
			`{"since":0,"changes":[{"id":%q,"action":"upsert",`+
				`"type":"asset","data":%s,"time":%d}]}`,
			uuid.NewV7(), assetDoc(uuid.NewV7(), owner, nil), stamp(1),
		)
	}

	tests := []struct {
		name       string
		claims     *auth.Claims
		body       string
		wantStatus int
		wantReason string
	}{
		{
			name: "machine token",
			claims: func() *auth.Claims {
				c := &auth.Claims{}
				c.Sub = "svc-account"
				c.Azp = "svc-account" // azp == sub: not delegated
				return c
			}(),
			body:       valid(),
			wantStatus: http.StatusForbidden,
			wantReason: diff.ReasonDelegationRequired,
		},
		{
			name: "non-uuid subject",
			claims: func() *auth.Claims {
				c := &auth.Claims{}
				c.Sub = "not-a-uuid"
				c.Azp = "test-client"
				return c
			}(),
			body:       valid(),
			wantStatus: http.StatusUnauthorized,
			wantReason: auth.ReasonInvalidToken,
		},
		{
			name:       "malformed body",
			claims:     claimsFor(owner),
			body:       `{"since":`,
			wantStatus: http.StatusBadRequest,
			wantReason: router.ReasonParseJSON,
		},
		{
			name:   "envelope validation",
			claims: claimsFor(owner),
			body: fmt.Sprintf(
				`{"since":-1,"changes":[{"id":%q,"action":"upsert",`+
					`"type":"asset","data":%s,"time":%d}]}`,
				uuid.NewV7(), assetDoc(uuid.NewV7(), owner, nil), stamp(1),
			),
			wantStatus: http.StatusBadRequest,
			wantReason: router.ReasonValidationFailed,
		},
		{
			name:   "unknown type",
			claims: claimsFor(owner),
			body: fmt.Sprintf(
				`{"since":0,"changes":[{"id":%q,"action":"upsert",`+
					`"type":"vehicle","data":%s,"time":%d}]}`,
				uuid.NewV7(), assetDoc(uuid.NewV7(), owner, nil), stamp(1),
			),
			wantStatus: http.StatusBadRequest,
			wantReason: diff.ReasonChangesRejected,
		},
		{
			name:   "scope violation",
			claims: claimsFor(owner),
			body: fmt.Sprintf(
				`{"since":0,"changes":[{"id":%q,"action":"upsert",`+
					`"type":"asset","data":%s,"time":%d}]}`,
				uuid.NewV7(),
				assetDoc(
					uuid.NewV7(),
					uuid.NewV7().String(),
					nil,
				), // foreign owner
				stamp(1),
			),
			wantStatus: http.StatusForbidden,
			wantReason: diff.ReasonChangesRejected,
		},
		{
			name:   "invalid payload",
			claims: claimsFor(owner),
			body: fmt.Sprintf(
				`{"since":0,"changes":[{"id":%q,"action":"upsert",`+
					`"type":"asset",`+
					`"data":{"id":%q,"user_id":%q,"name":""},"time":%d}]}`,
				uuid.NewV7(), uuid.NewV7(), owner, stamp(1),
			),
			wantStatus: http.StatusBadRequest,
			wantReason: diff.ReasonChangesRejected,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := serve(t, setup(), tt.claims)
			code, body := post(t, srv, tt.body)

			if code != tt.wantStatus {
				t.Errorf("status: got %d; want %d (body %v)",
					code, tt.wantStatus, body)
			}
			if got := body["reason"]; got != tt.wantReason {
				t.Errorf("reason: got %v; want %q", got, tt.wantReason)
			}
		})
	}

	t.Run("missing token", func(t *testing.T) {
		t.Parallel()
		srv := serve(t, setup(), claimsFor(owner))

		req, err := http.NewRequest(
			http.MethodPost, srv.URL+"/sync", strings.NewReader(valid()))
		if err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		// No Authorization header on purpose.

		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("should not have returned an error: %v", err)
		}
		defer func() { _ = res.Body.Close() }()

		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("status: got %d; want %d",
				res.StatusCode, http.StatusUnauthorized)
		}
	})

	t.Run("resync required", func(t *testing.T) {
		t.Parallel()
		f := setup()
		f.store.SetFloor(100)
		srv := serve(t, f, claimsFor(owner))

		code, body := post(t, srv, `{"since":5}`)
		if code != http.StatusGone {
			t.Errorf("status: got %d; want %d (body %v)",
				code, http.StatusGone, body)
		}
		if got := body["reason"]; got != diff.ReasonResyncRequired {
			t.Errorf("reason: got %v; want %q",
				got, diff.ReasonResyncRequired)
		}
	})
}
