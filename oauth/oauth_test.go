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
	"testing"
)

func TestVerifyRedirectURI(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		uri       string
		whitelist []string
		want      bool
	}{
		{
			name:      "exact match success",
			uri:       "https://deep.rent/auth",
			whitelist: []string{"https://deep.rent/auth"},
			want:      true,
		},
		{
			name:      "exact match fail",
			uri:       "https://deep.rent/callback",
			whitelist: []string{"https://deep.rent/auth"},
			want:      false,
		},
		{
			name:      "wildcard subdomain match success",
			uri:       "https://app.deep.rent/callback",
			whitelist: []string{"https://*.deep.rent/callback"},
			want:      true,
		},
		{
			name:      "wildcard subdomain match fail (mismatch)",
			uri:       "https://attacker.com/callback",
			whitelist: []string{"https://*.deep.rent/callback"},
			want:      false,
		},
		{
			name:      "wildcard path match success",
			uri:       "https://deep.rent/login?state=xyz",
			whitelist: []string{"https://deep.rent/login?*"},
			want:      true,
		},
		{
			name:      "wildcard port match success",
			uri:       "http://localhost:3000",
			whitelist: []string{"http://localhost:*"},
			want:      true,
		},
		{
			name:      "wildcard port match fail (mismatch host)",
			uri:       "http://attacker.com:3000",
			whitelist: []string{"http://localhost:*"},
			want:      false,
		},
		{
			name:      "wildcard port with path match success",
			uri:       "http://localhost:8080/callback",
			whitelist: []string{"http://localhost:*/callback"},
			want:      true,
		},
		{
			name:      "wildcard port with path and query match success",
			uri:       "http://localhost:4200/auth?state=xyz",
			whitelist: []string{"http://localhost:*/auth?state=*"},
			want:      true,
		},
		{
			name:      "strict query bypass attempt: unexpected query parameters",
			uri:       "https://deep.rent/callback?malicious_param=true",
			whitelist: []string{"https://deep.rent/callback"},
			want:      false,
		},
		{
			name:      "strict query bypass attempt: mismatched query",
			uri:       "https://deep.rent/callback?foo=bar",
			whitelist: []string{"https://deep.rent/callback?foo=baz"},
			want:      false,
		},
		{
			name:      "fragment rejection bypass attempt",
			uri:       "https://deep.rent/callback#access_token=stolen",
			whitelist: []string{"https://deep.rent/callback"},
			want:      false,
		},
		{
			name:      "bypass attempt: host-spanning wildcard",
			uri:       "https://attacker.com/deep.rent/",
			whitelist: []string{"https://*.deep.rent/*"},
			want:      false,
		},
		{
			name:      "bypass attempt: query parameter suffix match",
			uri:       "https://attacker.com/foo?bar=.deep.rent",
			whitelist: []string{"https://*.deep.rent"},
			want:      false,
		},
		{
			name:      "bypass attempt: subdomain suffix trick",
			uri:       "https://app.deep.rent.attacker.com/callback",
			whitelist: []string{"https://*.deep.rent/*"},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := VerifyRedirectURI(tt.uri, tt.whitelist)
			if got != tt.want {
				t.Errorf(
					"VerifyRedirectURI(%q, %v) = %t; want %t",
					tt.uri,
					tt.whitelist,
					got,
					tt.want,
				)
			}
		})
	}
}
