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

// Package idp defines the contract between the IAM server and external
// identity providers used for social login, such as Google or Apple.
//
// A [Provider] encapsulates the provider-specific OAuth 2.0 or OIDC exchange;
// the IAM server owns everything around it: CSRF protection (state generation
// and validation), session establishment, and account linking. Shared OIDC
// client utilities live in [github.com/deep-rent/nexus/sec/iam/idp/oidc];
// concrete providers live in the sibling packages
// [github.com/deep-rent/nexus/sec/iam/idp/google] and
// [github.com/deep-rent/nexus/sec/iam/idp/apple].
package idp

import (
	"context"
	"net/http"
)

// Claimant represents a user identity verified by an external provider.
type Claimant struct {
	// Subject is the unique identifier of the user at the external provider.
	Subject string `json:"sub"`
	// Email is the user's primary email address.
	Email string `json:"email,omitempty"`
	// EmailVerified indicates whether the email address has been verified.
	EmailVerified bool `json:"email_verified,omitempty"`
	// Name is the user's full name.
	Name string `json:"name,omitempty"`
	// Picture is the URL of the user's profile picture.
	Picture string `json:"picture,omitempty"`
}

// Provider defines the contract for external social authentication
// providers (e.g., Google, GitHub, Apple).
//
// Implementations are responsible for defining the provider-specific OAuth 2.0
// or OIDC flows. The IAM server manages CSRF protection (state generation
// and validation) and the final local session creation, allowing
// implementations to focus purely on the external exchange.
type Provider interface {
	// AuthURL generates the authorization URL to redirect the user-agent.
	//
	// Implementations must append the provided state string to the URL's
	// query parameters (e.g., `?state=...`). The redirect URI should point
	// to the server's registered ExternalCallback endpoint.
	AuthURL(ctx context.Context, state string) (string, error)
	// Exchange handles the callback request and returns the external
	// identity information.
	//
	// Implementations should extract the authorization code from the request
	// and exchange it securely via the external provider's API. Note that the
	// IAM server already validates the state parameter against a secure
	// cookie prior to calling this method, so implementations do not need to
	// perform additional CSRF checks.
	Exchange(ctx context.Context, req *http.Request) (Claimant, error)
}
