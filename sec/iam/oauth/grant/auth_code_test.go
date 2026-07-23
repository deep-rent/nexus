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

package grant

import (
	"net/url"
	"testing"
	"time"

	"uuid"

	"github.com/deep-rent/nexus/sec/iam/oauth"
	"github.com/deep-rent/nexus/sec/iam/oauth/pkce"
)

func TestAuthCodeGrant(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_752_000_000, 0)
	clientID := uuid.New()
	subjectID := uuid.New()

	verifier, err := pkce.Verifier(t.Context())
	if err != nil {
		t.Fatalf("failed to generate verifier: %v", err)
	}
	challenge, err := pkce.Challenge(verifier, pkce.MethodS256)
	if err != nil {
		t.Fatalf("failed to generate challenge: %v", err)
	}

	client := &fakeClient{id: clientID}

	code := func() oauth.AuthCode {
		return oauth.AuthCode{
			Code:                newDigest("code-1"),
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
		code     oauth.AuthCode
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
			wantCode: oauth.ErrorCodeInvalidRequest,
		},
		{
			name: "missing verifier",
			seed: true,
			code: code(),
			data: url.Values{
				"code": {"code-1"},
			},
			wantCode: oauth.ErrorCodeInvalidRequest,
		},
		{
			name:     "unknown code",
			seed:     false,
			data:     form(),
			wantCode: oauth.ErrorCodeInvalidGrant,
		},
		{
			name: "expired code",
			seed: true,
			code: func() oauth.AuthCode {
				c := code()
				c.ExpiresAt = now.Add(-time.Minute).Unix()
				return c
			}(),
			data:     form(),
			wantCode: oauth.ErrorCodeInvalidGrant,
		},
		{
			name: "client mismatch",
			seed: true,
			code: func() oauth.AuthCode {
				c := code()
				c.ClientID = uuid.New()
				return c
			}(),
			data:     form(),
			wantCode: oauth.ErrorCodeInvalidGrant,
		},
		{
			name: "missing redirect uri",
			seed: true,
			code: code(),
			data: url.Values{
				"code":          {"code-1"},
				"code_verifier": {verifier},
			},
			wantCode: oauth.ErrorCodeInvalidRequest,
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
			wantCode: oauth.ErrorCodeInvalidGrant,
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
			wantCode: oauth.ErrorCodeInvalidGrant,
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

			store := newFakeTokens()
			if tt.seed {
				seed(t, store.authCodes, tt.code)
			}

			pro := newProposal(client, store, tt.data, now)
			iss, err := AuthCode().Authorize(t.Context(), pro)

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
			if _, found, _ := store.authCodes.Get(
				t.Context(),
				newDigest("code-1"),
			); found {
				t.Error("authorization code should have been deleted after use")
			}
		})
	}

	t.Run("single use", func(t *testing.T) {
		t.Parallel()

		store := newFakeTokens()
		seed(t, store.authCodes, code())

		pro := newProposal(client, store, form(), now)
		if _, err := AuthCode().Authorize(t.Context(), pro); err != nil {
			t.Fatalf("first exchange should succeed: %v", err)
		}

		pro = newProposal(client, store, form(), now)
		_, err := AuthCode().Authorize(t.Context(), pro)
		if got := errCode(err); got != oauth.ErrorCodeInvalidGrant {
			t.Fatalf(
				"replay should fail with %q; got %q",
				oauth.ErrorCodeInvalidGrant,
				got,
			)
		}
	})
}
