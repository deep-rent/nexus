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

// Package google implements "Sign in with Google" as an
// [idp.Provider].
//
// The provider drives the OIDC Authorization Code flow against Google's
// endpoints: it redirects the user-agent to Google's consent screen,
// exchanges the returned authorization code for an ID token, and verifies
// that token against Google's published JWKS.
//
// # Usage
//
//	p := google.New(google.Config{
//	  ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
//	  ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
//	  RedirectURI:  "https://id.example.com/oauth/callback/google",
//	})
//
//	// Keep Google's signing keys fresh in the background.
//	scheduler.Dispatch(p.Keys())
//
//	s := iam.New(cfg, iam.WithIdentityProvider("google", p))
package google
