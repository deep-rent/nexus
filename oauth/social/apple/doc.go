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

// Package apple implements "Sign in with Apple" as an
// [oauth.IdentityProvider].
//
// Apple's flow deviates from vanilla OIDC in three ways, all handled here:
//
//   - The client secret is not static: every token exchange is
//     authenticated with a short-lived ES256 JWT signed by the developer's
//     private key (the .p8 file downloaded from the Apple Developer portal).
//   - When scopes are requested, Apple delivers the callback as a cross-site
//     POST (response_mode=form_post) rather than a GET redirect. The core
//     [oauth.Server] accepts both.
//   - The user's name is not part of the ID token. Apple posts a one-time
//     "user" JSON payload alongside the very first authorization; it is
//     merged into the returned [oauth.Claimant].
//
// # Usage
//
//	p := apple.New(apple.Config{
//	  ClientID:    "com.example.web",     // Services ID
//	  TeamID:      "94Z27KF87Q",
//	  KeyID:       "3JD9C6QQ7A",
//	  PrivateKey:  keyPEM,                // contents of AuthKey_XXX.p8
//	  RedirectURI: "https://id.example.com/oauth/callback/apple",
//	})
//
//	// Keep Apple's signing keys fresh in the background.
//	scheduler.Dispatch(p.Keys())
//
//	s := oauth.New(cfg, oauth.WithIdentityProvider("apple", p))
package apple
