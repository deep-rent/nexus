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

	"github.com/deep-rent/nexus/sec/oauth/pkce"
)

func TestAuthCodeGrant(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_752_000_000, 0)
	clientID := uuid.New()
	subjectID := uuid.New()

	verifier, err := pkce.Verifier(64)
	if err != nil {
		t.Fatalf("failed to generate verifier: %v", err)
	}
	challenge, err := pkce.Challenge(verifier, pkce.MethodS256)
	if err != nil {
		t.Fatalf("failed to generate challenge: %v", err)
	}

	client := &fakeClient{id: clientID}

	code := func() AuthCode {
		return AuthCode{
			Code:                NewDigest("code-1"),
			ClientID:            clientID,
			RedirectURI:         "https://app.example.com/callback",
			Scope:               "read write",
			SubjectID:           subjectID,
			CodeChallenge:       challenge,
			CodeChallengeMethod: pkce.MethodS256,
			ExpiresAt:           now.Add(5 * time.Minute).Unix(),
		}
	}

	form := func() url.Values {
		return url.Values{
			"code":          {"code-1"},
			"code_verifier": {verifier},
			"redirect_uri":  {"https://app.example.com/callback"},
		}
	}

	tests := []struct {
		name     string
		code     AuthCode
		seed     bool
		data     url.Values
		wantCode string
	}{
		{
			name: "missing code",
			seed: true,
			code: code(),
			data: url.Values{
				"code_verifier": {verifier},
			},
			wantCode: ErrorCodeInvalidRequest,
		},
		{
			name: "missing verifier",
			seed: true,
			code: code(),
			data: url.Values{
				"code": {"code-1"},
			},
			wantCode: ErrorCodeInvalidRequest,
		},
		{
			name:     "unknown code",
			seed:     false,
			data:     form(),
			wantCode: ErrorCodeInvalidGrant,
		},
		{
			name: "expired code",
			seed: true,
			code: func() AuthCode {
				c := code()
				c.ExpiresAt = now.Add(-time.Minute).Unix()
				return c
			}(),
			data:     form(),
			wantCode: ErrorCodeInvalidGrant,
		},
		{
			name: "client mismatch",
			seed: true,
			code: func() AuthCode {
				c := code()
				c.ClientID = uuid.New()
				return c
			}(),
			data:     form(),
			wantCode: ErrorCodeInvalidGrant,
		},
		{
			name: "missing redirect uri",
			seed: true,
			code: code(),
			data: url.Values{
				"code":          {"code-1"},
				"code_verifier": {verifier},
			},
			wantCode: ErrorCodeInvalidRequest,
		},
		{
			name: "redirect uri mismatch",
			seed: true,
			code: code(),
			data: url.Values{
				"code":          {"code-1"},
				"code_verifier": {verifier},
				"redirect_uri":  {"https://evil.example.com/callback"},
			},
			wantCode: ErrorCodeInvalidGrant,
		},
		{
			name: "pkce failure",
			seed: true,
			code: code(),
			data: url.Values{
				"code": {"code-1"},
				"code_verifier": {
					"wrong-verifier-wrong-verifier-wrong-verifier",
				},
				"redirect_uri": {"https://app.example.com/callback"},
			},
			wantCode: ErrorCodeInvalidGrant,
		},
		{
			name:     "success",
			seed:     true,
			code:     code(),
			data:     form(),
			wantCode: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := newFakeSessionStore()
			if tt.seed {
				store.authCodes[tt.code.Code] = tt.code
			}

			pro := newProposal(client, store, tt.data, now)
			iss, err := AuthCodeGrant().Authorize(t.Context(), pro)

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
			if got, want := iss.Scope, "read write"; got != want {
				t.Errorf("got scope %q; want %q", got, want)
			}
			if !iss.Refreshable {
				t.Error("issuance should be refreshable")
			}
			if _, ok := store.authCodes[NewDigest("code-1")]; ok {
				t.Error("authorization code should have been deleted after use")
			}
		})
	}

	t.Run("single use", func(t *testing.T) {
		t.Parallel()

		store := newFakeSessionStore()
		store.authCodes[NewDigest("code-1")] = code()

		pro := newProposal(client, store, form(), now)
		if _, err := AuthCodeGrant().Authorize(t.Context(), pro); err != nil {
			t.Fatalf("first exchange should succeed: %v", err)
		}

		pro = newProposal(client, store, form(), now)
		_, err := AuthCodeGrant().Authorize(t.Context(), pro)
		if got := errCode(err); got != ErrorCodeInvalidGrant {
			t.Fatalf(
				"replay should fail with %q; got %q",
				ErrorCodeInvalidGrant,
				got,
			)
		}
	})
}
