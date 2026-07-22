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
	"context"
	"net/http"

	"github.com/deep-rent/nexus/sec/iam/oauth"
)

// clientCredentials implements the [oauth.Grant] interface for
// machine-to-machine authentication.
type clientCredentials struct{}

// ClientCredentials returns a new grant implementation for the Client
// Credentials flow.
//
// Register the result on the IAM server via
// [github.com/deep-rent/nexus/sec/iam.WithGrant] to enable this grant.
func ClientCredentials() oauth.Grant {
	return clientCredentials{}
}

// Type implements [oauth.Grant].
func (g clientCredentials) Type() oauth.GrantType {
	return oauth.GrantTypeClientCredentials
}

// Authorize implements [oauth.Grant].
func (g clientCredentials) Authorize(
	ctx context.Context,
	pro *oauth.Proposal,
) (*oauth.Issuance, error) {
	// Validate that the client is permitted to use the requested scopes.
	scope := pro.Get("scope")
	if scope != "" && !oauth.CanUseScope(pro.Client, scope) {
		return nil, &oauth.Error{
			Status:      http.StatusBadRequest,
			Code:        oauth.ErrorCodeInvalidScope,
			Description: "scope is not allowed for client",
		}
	}

	// The zero Subject marks the client itself as the token subject.
	return &oauth.Issuance{
		Scope:       scope,
		Refreshable: false,
	}, nil
}

var _ oauth.Grant = (*clientCredentials)(nil)
