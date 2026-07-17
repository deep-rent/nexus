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
	"context"
	"net/http"
)

// clientCredentialsGrant implements the [Grant] interface for
// machine-to-machine authentication.
type clientCredentialsGrant struct{}

// ClientCredentialsGrant returns a new grant implementation for the Client
// Credentials flow.
//
// Pass the result to [New] using [WithGrant] to enable this grant.
func ClientCredentialsGrant() Grant {
	return clientCredentialsGrant{}
}

// Type implements [Grant].
func (g clientCredentialsGrant) Type() GrantType {
	return GrantTypeClientCredentials
}

// Authorize implements [Grant].
func (g clientCredentialsGrant) Authorize(
	ctx context.Context,
	pro *Proposal,
) (*Issuance, error) {
	// Validate that the client is permitted to use the requested scopes.
	scope := pro.Get("scope")
	if scope != "" && !canUseScope(pro.Client, scope) {
		return nil, &Error{
			Status:      http.StatusBadRequest,
			Code:        ErrorCodeInvalidScope,
			Description: "scope is not allowed for client",
		}
	}

	// The zero Subject marks the client itself as the token subject.
	return &Issuance{
		Scope:       scope,
		Refreshable: false,
	}, nil
}

var _ Grant = (*clientCredentialsGrant)(nil)
