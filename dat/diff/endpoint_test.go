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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"uuid"

	"github.com/deep-rent/nexus/sec/auth"
	"github.com/deep-rent/nexus/dat/diff"
	"github.com/deep-rent/nexus/sec/jose/jwt"
	"github.com/deep-rent/nexus/net/router"
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
func claimsFor(userID uuid.UUID, teams ...uuid.UUID) *auth.Claims {
	c := &auth.Claims{Teams: teams}
	c.Sub = userID.String()
	c.Azp = uuid.NewV7().String() // acting on behalf of the user
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

// get requests a single document and returns the status code and decoded
// body.
func get(
	t *testing.T,
	srv *httptest.Server,
	path string,
) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
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
	owner := uuid.NewV7()
	srv := serve(t, f, claimsFor(owner))

	doc := assetDoc(uuid.NewV7(), owner, uuid.Nil())
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

	owner := uuid.NewV7()

	valid := func() string {
		return fmt.Sprintf(
			`{"since":0,"changes":[{"id":%q,"action":"upsert",`+
				`"type":"asset","data":%s,"time":%d}]}`,
			uuid.NewV7(), assetDoc(uuid.NewV7(), owner, uuid.Nil()), stamp(1),
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
				svc := uuid.NewV7()
				c := &auth.Claims{}
				c.Sub = svc.String()
				c.Azp = svc.String() // azp == sub: not delegated
				return c
			}(),
			body:       valid(),
			wantStatus: http.StatusForbidden,
			wantReason: auth.ReasonDelegationRequired,
		},
		{
			name: "zero subject",
			claims: func() *auth.Claims {
				c := &auth.Claims{}
				c.Azp = uuid.NewV7().
					String()
					// delegated, but no usable subject
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
				uuid.NewV7(),
				assetDoc(uuid.NewV7(), owner, uuid.Nil()),
				stamp(1),
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
				uuid.NewV7(),
				assetDoc(uuid.NewV7(), owner, uuid.Nil()),
				stamp(1),
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
					uuid.NewV7(),
					uuid.Nil(),
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

func TestEndpoint_Document(t *testing.T) {
	t.Parallel()

	f := setup()
	owner := uuid.NewV7()
	srv := serve(t, f, claimsFor(owner))

	// Seed one document through the sync endpoint.
	id := uuid.NewV7()
	code, body := post(t, srv, fmt.Sprintf(
		`{"since":0,"changes":[{"id":%q,"action":"upsert","type":"asset",`+
			`"data":%s,"time":%d}]}`,
		uuid.NewV7(), assetDoc(id, owner, uuid.Nil()), stamp(1),
	))
	if code != http.StatusOK {
		t.Fatalf("seed status: got %d; want %d (body %v)",
			code, http.StatusOK, body)
	}

	code, body = get(t, srv, "/asset/"+id.String())
	if code != http.StatusOK {
		t.Fatalf("status: got %d; want %d (body %v)",
			code, http.StatusOK, body)
	}
	if got := body["type"]; got != "asset" {
		t.Errorf("type: got %v; want %q", got, "asset")
	}
	if _, ok := body["time"].(float64); !ok {
		t.Errorf("time: got %v; want a timestamp", body["time"])
	}
	data, ok := body["data"].(map[string]any)
	if !ok {
		t.Fatalf("data: got %v; want a document payload", body["data"])
	}
	if got := data["id"]; got != id.String() {
		t.Errorf("data id: got %v; want %q", got, id.String())
	}
}

func TestEndpoint_Document_Errors(t *testing.T) {
	t.Parallel()

	owner := uuid.NewV7()
	foreign := uuid.NewV7() // a document of another user

	seed := func(f *fixture, srv *httptest.Server) {
		t.Helper()
		code, body := post(t, srv, fmt.Sprintf(
			`{"since":0,"changes":[{"id":%q,"action":"upsert",`+
				`"type":"asset","data":%s,"time":%d}]}`,
			uuid.NewV7(), assetDoc(foreign, owner, uuid.Nil()), stamp(1),
		))
		if code != http.StatusOK {
			t.Fatalf("seed status: got %d; want %d (body %v)",
				code, http.StatusOK, body)
		}
	}

	tests := []struct {
		name       string
		claims     *auth.Claims
		path       string
		wantStatus int
		wantReason string
	}{
		{
			name: "machine token",
			claims: func() *auth.Claims {
				svc := uuid.NewV7()
				c := &auth.Claims{}
				c.Sub = svc.String()
				c.Azp = svc.String() // azp == sub: not delegated
				return c
			}(),
			path:       "/asset/" + uuid.NewV7().String(),
			wantStatus: http.StatusForbidden,
			wantReason: auth.ReasonDelegationRequired,
		},
		{
			name:       "invalid id",
			claims:     claimsFor(owner),
			path:       "/asset/not-a-uuid",
			wantStatus: http.StatusBadRequest,
			wantReason: router.ReasonValidationFailed,
		},
		{
			name:       "unknown model",
			claims:     claimsFor(owner),
			path:       "/vehicle/" + uuid.NewV7().String(),
			wantStatus: http.StatusNotFound,
			wantReason: diff.ReasonUnknownModel,
		},
		{
			name:       "absent document",
			claims:     claimsFor(owner),
			path:       "/asset/" + uuid.NewV7().String(),
			wantStatus: http.StatusNotFound,
			wantReason: router.ReasonNotFound,
		},
		{
			name:       "foreign document",
			claims:     claimsFor(uuid.NewV7()), // not the owner
			path:       "/asset/" + foreign.String(),
			wantStatus: http.StatusNotFound,
			wantReason: router.ReasonNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := setup()

			// Seeding requires owner claims; serve the test claims through a
			// second server sharing the same fixture.
			seeder := serve(t, f, claimsFor(owner))
			seed(f, seeder)

			srv := serve(t, f, tt.claims)
			code, body := get(t, srv, tt.path)

			if code != tt.wantStatus {
				t.Errorf("status: got %d; want %d (body %v)",
					code, tt.wantStatus, body)
			}
			if got := body["reason"]; got != tt.wantReason {
				t.Errorf("reason: got %v; want %q", got, tt.wantReason)
			}
		})
	}
}

// getConditional performs a conditional document GET, returning the raw
// response with its body drained into buf.
func getConditional(
	t *testing.T,
	srv *httptest.Server,
	path string,
	ifNoneMatch string,
) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	req.Header.Set("Authorization", "Bearer token")
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}

	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	defer func() { _ = res.Body.Close() }()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("should not have returned an error: %v", err)
	}
	return res, body
}

func TestEndpoint_Document_Conditional(t *testing.T) {
	t.Parallel()

	f := setup()
	owner := uuid.NewV7()
	srv := serve(t, f, claimsFor(owner))

	id := uuid.NewV7()
	code, body := post(t, srv, fmt.Sprintf(
		`{"since":0,"changes":[{"id":%q,"action":"upsert","type":"asset",`+
			`"data":%s,"time":%d}]}`,
		uuid.NewV7(), assetDoc(id, owner, uuid.Nil()), stamp(1),
	))
	if code != http.StatusOK {
		t.Fatalf("seed status: got %d; want %d (body %v)",
			code, http.StatusOK, body)
	}
	path := "/asset/" + id.String()

	// The initial response carries a strong ETag and private caching.
	res, _ := getConditional(t, srv, path, "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d; want %d", res.StatusCode, http.StatusOK)
	}
	etag := res.Header.Get("ETag")
	if len(etag) < 3 || !strings.HasPrefix(etag, `"`) ||
		!strings.HasSuffix(etag, `"`) {
		t.Fatalf("etag: got %q; want a quoted entity tag", etag)
	}
	if got := res.Header.Get("Cache-Control"); got != "private, no-cache" {
		t.Errorf("cache-control: got %q; want %q", got, "private, no-cache")
	}

	// Matching validators answer 304 without a body; the ETag survives so
	// caches can refresh their metadata.
	for _, match := range []string{
		etag,
		"W/" + etag,
		`"stale", ` + etag,
		"*",
	} {
		res, raw := getConditional(t, srv, path, match)
		if res.StatusCode != http.StatusNotModified {
			t.Errorf("if-none-match %q: got status %d; want %d",
				match, res.StatusCode, http.StatusNotModified)
		}
		if len(raw) != 0 {
			t.Errorf("if-none-match %q: got body %q; want empty", match, raw)
		}
		if got := res.Header.Get("ETag"); got != etag {
			t.Errorf("if-none-match %q: got etag %q; want %q",
				match, got, etag)
		}
	}

	// A stale validator answers the full document.
	res, raw := getConditional(t, srv, path, `"stale"`)
	if res.StatusCode != http.StatusOK {
		t.Errorf("stale validator: got status %d; want %d",
			res.StatusCode, http.StatusOK)
	}
	if len(raw) == 0 {
		t.Error("stale validator: got empty body; want the document")
	}

	// A newer write rotates the ETag, so a held validator stops matching.
	code, body = post(t, srv, fmt.Sprintf(
		`{"since":0,"changes":[{"id":%q,"action":"upsert","type":"asset",`+
			`"data":%s,"time":%d}]}`,
		uuid.NewV7(), assetDoc(id, owner, uuid.Nil()), stamp(2),
	))
	if code != http.StatusOK {
		t.Fatalf("update status: got %d; want %d (body %v)",
			code, http.StatusOK, body)
	}
	res, _ = getConditional(t, srv, path, etag)
	if res.StatusCode != http.StatusOK {
		t.Errorf("rotated etag: got status %d; want %d",
			res.StatusCode, http.StatusOK)
	}
	if got := res.Header.Get("ETag"); got == etag {
		t.Errorf("rotated etag: got unchanged %q; want a new tag", got)
	}
}
