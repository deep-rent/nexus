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

// Package oauth implements the core protocols for an OAuth 2.0 authorization
// server.
//
// The package provides a flexible and extensible framework for issuing access
// tokens to clients. It abstracts the complexity of the OAuth 2.0 flows,
// including Authorization Code, Client Credentials, and Refresh Token grants,
// while allowing developers to provide custom implementations for client and
// session management.
//
// # Architecture
//
// The core of the package is the [Server], which manages the lifecycle of
// authorization requests and token issuance. It relies on a set of interfaces
// ([ClientStore], [SubjectStore], [SessionStore]) that must be implemented to
// bridge the library with the underlying database or persistence layer.
//
// # Usage
//
// To use this package, define a [Config] with your store implementations
// and initialize a [Server] using the desired [Grant] types as options.
//
// Example:
//
//	// 1. Define the configuration with mandatory stores and key vault.
//	cfg := oauth.Config{
//	  Vault:            myVault,
//	  Clients:          myClientStore,
//	  Sessions:         mySessionStore,
//	  Subjects:         mySubjectStore,
//	  Issuer:           "https://id.example.com",
//	  LoginTerminalURI: "https://app.example.com/login",
//	  LoginRedirectURI: "https://app.example.com/dashboard",
//	}
//
//	// 2. Initialize the server and register grants or identity providers.
//	// New panics on invalid configuration.
//	s := oauth.New(cfg,
//	  oauth.WithGrant(oauth.AuthCodeGrant()),
//	  oauth.WithGrant(oauth.ClientCredentialsGrant()),
//	  oauth.WithGrant(oauth.RefreshTokenGrant()),
//	  oauth.WithIdentityProvider("google", myGoogleProvider),
//	)
//
//	// 3. Mount the endpoints onto a router.
//	r := router.New()
//	s.Mount(r, "/oauth")
//
//	// 4. Start serving.
//	http.ListenAndServe(":8080", r)
//
// # Two-factor logins
//
// Password logins can be stepped up with a one-time password delivered over
// a side channel; see [WithOTPChannel]. When at least one channel is
// registered, subjects that have enrolled a [SecondFactor] receive an
// [OTPChallengeResponse] instead of a session from the login endpoint and
// confirm the code via [Server.VerifyOTP] (or request redelivery via
// [Server.ResendOTP]). Channels are registered under free-form names that
// enrollments refer to; delivery is abstracted by the otp package:
//
//	s := oauth.New(cfg,
//	  oauth.WithGrant(oauth.AuthCodeGrant()),
//	  oauth.WithOTPChannel(
//	    oauth.SecondFactorChannelSMS,
//	    otp.SMS(smsSender, "+15551234567", ""),
//	  ),
//	  oauth.WithOTPChannel(
//	    oauth.SecondFactorChannelEmail,
//	    otp.Mail(mailSender, from, "template-id", ""),
//	  ),
//	)
//
// # Passkeys
//
// WebAuthn passkeys are supported both as a first-party web login and as a
// direct token grant for native apps; see [WithWebAuthn]. Web clients run
// the registration and login ceremonies against the /webauthn endpoints and
// end up with the same session cookie as a password login, while native
// apps exchange an assertion for tokens at the token endpoint using
// [GrantTypeWebAuthn]:
//
//	s := oauth.New(cfg,
//	  oauth.WithGrant(oauth.AuthCodeGrant()),
//	  oauth.WithWebAuthn(oauth.WebAuthnConfig{
//	    RPID:          "example.com",
//	    RPDisplayName: "Example",
//	    RPOrigins:     []string{"https://app.example.com"},
//	  }),
//	)
//
// # Operational notes
//
// The server issues stateless JWT access tokens; only refresh tokens can be
// revoked. The authorization endpoint grants implicit consent: any resource
// owner with an active session is treated as having approved the requested
// scopes, which is appropriate for first-party clients only.
//
// Set [Config.Throttle] to rate limit the credential-verifying endpoints
// and slow down brute-force attempts; see [throttle.Throttle] for the
// trade-offs. Because its buckets live in memory, it complements rather than
// replaces volumetric rate limiting at the load balancer or reverse proxy.
//
// Deployments must provide the remaining protections that fall outside this
// package: serve all endpoints over TLS (cookies are marked secure), and
// back the store interfaces with implementations that honor the atomicity
// and TTL contracts documented on [SessionStore].
package oauth
