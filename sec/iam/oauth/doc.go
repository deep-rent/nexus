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

// Package oauth defines the wire-level vocabulary of the OAuth 2.0
// authorization framework: grant types, the [Grant] contract and its
// [Proposal]/[Issuance] exchange, RFC 6749 error codes, the request and
// response payloads of the token machinery, and the digest-keyed [TokenStores]
// persistence contract for authorization codes, refresh tokens, and device
// codes.
//
// The package is deliberately free of transport and policy: it contains no
// HTTP handlers and takes no decisions. The authorization server lives in the
// parent package, [github.com/deep-rent/nexus/sec/iam]; the standard grant
// implementations live in
// [github.com/deep-rent/nexus/sec/iam/oauth/grant]; PKCE helpers live in
// [github.com/deep-rent/nexus/sec/iam/oauth/pkce].
//
// # Bearer artifacts and digests
//
// Every bearer artifact — authorization code, refresh token, device code, or
// user code — is fingerprinted as a [Digest] before it crosses the
// [TokenStores] boundary, so store implementations never see plaintext
// secrets. Grants obtain digests via [Proposal.Digest], which honors the
// hasher the authorization server was configured with.
package oauth
