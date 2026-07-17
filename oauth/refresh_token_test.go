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

package oauth

import (
	"net/url"
	"testing"
	"time"

	"uuid"
)

func TestRefreshTokenGrant(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_752_000_000, 0)
	clientID := uuid.New()
	subjectID := uuid.New()

	client := &fakeClient{id: clientID}

	token := func() RefreshToken {
		return RefreshToken{
			Token:     "token-1",
			ClientID:  clientID,
			SubjectID: subjectID,
			Scope:     "read write",
			ExpiresAt: now.Add(24 * time.Hour).Unix(),
		}
	}

	tests := []struct {
		name      string
		token     RefreshToken
		seed      bool
		data      url.Values
		wantCode  string
		wantScope string
	}{
		{
			name:     "missing token",
			seed:     true,
			token:    token(),
			data:     url.Values{},
			wantCode: ErrorCodeInvalidRequest,
		},
		{
			name:     "unknown token",
			seed:     false,
			data:     url.Values{"refresh_token": {"token-1"}},
			wantCode: ErrorCodeInvalidGrant,
		},
		{
			name: "expired token",
			seed: true,
			token: func() RefreshToken {
				r := token()
				r.ExpiresAt = now.Add(-time.Minute).Unix()
				return r
			}(),
			data:     url.Values{"refresh_token": {"token-1"}},
			wantCode: ErrorCodeInvalidGrant,
		},
		{
			name: "client mismatch",
			seed: true,
			token: func() RefreshToken {
				r := token()
				r.ClientID = uuid.New()
				return r
			}(),
			data:     url.Values{"refresh_token": {"token-1"}},
			wantCode: ErrorCodeInvalidGrant,
		},
		{
			name:  "scope narrowing",
			seed:  true,
			token: token(),
			data: url.Values{
				"refresh_token": {"token-1"},
				"scope":         {"read"},
			},
			wantScope: "read",
		},
		{
			name:  "scope broadening rejected",
			seed:  true,
			token: token(),
			data: url.Values{
				"refresh_token": {"token-1"},
				"scope":         {"read admin"},
			},
			wantCode: ErrorCodeInvalidScope,
		},
		{
			name:      "success",
			seed:      true,
			token:     token(),
			data:      url.Values{"refresh_token": {"token-1"}},
			wantScope: "read write",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := newFakeSessionStore()
			if tt.seed {
				store.refreshTokens[tt.token.Token] = tt.token
			}

			pro := newProposal(client, store, tt.data, now)
			iss, err := RefreshTokenGrant().Authorize(t.Context(), pro)

			if tt.wantCode != "" {
				if got := errCode(err); got != tt.wantCode {
					t.Fatalf(
						"got error code %q; want %q (err: %v)",
						got,
						tt.wantCode,
						err,
					)
				}
				return
			}

			if err != nil {
				t.Fatalf("should not have returned an error: %v", err)
			}
			if iss.Subject != subjectID {
				t.Errorf("got subject %v; want %v", iss.Subject, subjectID)
			}
			if iss.Scope != tt.wantScope {
				t.Errorf("got scope %q; want %q", iss.Scope, tt.wantScope)
			}
			if !iss.Refreshable {
				t.Error("issuance should be refreshable")
			}
			if _, ok := store.refreshTokens["token-1"]; ok {
				t.Error("refresh token should have been rotated out")
			}
		})
	}

	t.Run("rotation prevents reuse", func(t *testing.T) {
		t.Parallel()

		store := newFakeSessionStore()
		store.refreshTokens["token-1"] = token()

		data := url.Values{"refresh_token": {"token-1"}}

		pro := newProposal(client, store, data, now)
		if _, err := RefreshTokenGrant().Authorize(t.Context(), pro); err != nil {
			t.Fatalf("first exchange should succeed: %v", err)
		}

		pro = newProposal(client, store, data, now)
		_, err := RefreshTokenGrant().Authorize(t.Context(), pro)
		if got := errCode(err); got != ErrorCodeInvalidGrant {
			t.Fatalf(
				"reuse should fail with %q; got %q",
				ErrorCodeInvalidGrant,
				got,
			)
		}
	})
}
