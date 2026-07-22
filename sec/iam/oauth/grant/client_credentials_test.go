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
)

func TestClientCredentialsGrant(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_752_000_000, 0)

	client := &fakeClient{
		id:     uuid.New(),
		scopes: []string{"read", "write"},
	}

	tests := []struct {
		name     string
		scope    string
		wantCode string
	}{
		{
			name:  "no scope",
			scope: "",
		},
		{
			name:  "allowed scope",
			scope: "read",
		},
		{
			name:  "allowed multi scope",
			scope: "read write",
		},
		{
			name:     "disallowed scope",
			scope:    "admin",
			wantCode: oauth.ErrorCodeInvalidScope,
		},
		{
			name:     "partially disallowed scope",
			scope:    "read admin",
			wantCode: oauth.ErrorCodeInvalidScope,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			data := url.Values{}
			if tt.scope != "" {
				data.Set("scope", tt.scope)
			}

			pro := newProposal(client, newFakeTokenStore(), data, now)
			iss, err := ClientCredentials().Authorize(t.Context(), pro)

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
			if iss.Subject != uuid.Nil() {
				t.Errorf("got subject %v; want the zero UUID", iss.Subject)
			}
			if iss.Scope != tt.scope {
				t.Errorf("got scope %q; want %q", iss.Scope, tt.scope)
			}
			if iss.Refreshable {
				t.Error("machine-to-machine issuance should not be refreshable")
			}
		})
	}
}
