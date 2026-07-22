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

// Package grant provides the standard OAuth 2.0 grant implementations:
// Authorization Code with mandatory PKCE ([AuthCode]), Client Credentials
// ([ClientCredentials]), Refresh Token rotation ([RefreshToken]), and the
// Device Authorization flow ([DeviceCode]).
//
// Each constructor returns an [oauth.Grant] that is registered on the IAM
// server via [github.com/deep-rent/nexus/sec/iam.WithGrant]:
//
//	s := iam.New(cfg,
//	  iam.WithGrant(grant.AuthCode()),
//	  iam.WithGrant(grant.ClientCredentials()),
//	  iam.WithGrant(grant.RefreshToken()),
//	)
//
// Grants are pure protocol logic: they receive the authenticated client and
// the raw request form through an [oauth.Proposal], validate the
// grant-specific credentials against the [oauth.TokenStore], and return an
// [oauth.Issuance] describing the tokens to mint. Transport, throttling, and
// token signing remain the server's concern.
package grant
