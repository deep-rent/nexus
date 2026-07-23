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

// Package oauth implements an OAuth 2.0 authorization server and the
// wire-level vocabulary it speaks: grant types, the [Grant] contract and its
// [Proposal]/[Issuance] exchange, RFC 6749 error codes, the request and
// response payloads of the token machinery, and the digest-keyed
// [TokenStores] persistence contract.
//
// # The server
//
// The [Server] serves the token, authorization, introspection, revocation,
// and device authorization endpoints, together with the RFC 8414 metadata
// and JWKS documents. It is deliberately login-agnostic: everything it knows
// about resource owners arrives through two narrow seams — a
// [SessionResolver] that authenticates the request's resource owner and an
// [OwnerResolver] that resolves owners for claim minting — so it can stand
// alone or be composed with a login system.
//
// A standalone machine-to-machine issuer needs neither seam:
//
//	s := oauth.NewServer(oauth.ServerConfig{
//	  Vault:   myVault,
//	  Clients: myClientStore,
//	  Tokens:  myTokenStores,
//	  Issuer:  "https://id.example.com",
//	}, oauth.WithGrant(grant.ClientCredentials()))
//
//	r := router.New()
//	s.Mount(r, "/oauth")
//
// The full identity stack — password and passwordless logins, passkeys,
// social login, device trust — lives in the parent package,
// [github.com/deep-rent/nexus/sec/iam], whose Server embeds this one and
// supplies the resolver seams from its session machinery. The standard grant
// implementations live in [github.com/deep-rent/nexus/sec/iam/oauth/grant];
// PKCE helpers live in [github.com/deep-rent/nexus/sec/iam/oauth/pkce].
//
// # Bearer artifacts and digests
//
// Every bearer artifact — authorization code, refresh token, device code, or
// user code — is fingerprinted as a [Digest] before it crosses the
// [TokenStores] boundary, so store implementations never see plaintext
// secrets. Grants obtain digests via [Proposal.Digest], which honors the
// hasher the authorization server was configured with.
package oauth
