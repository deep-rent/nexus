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

package apple

import (
	"net/http"
)

// Config carries the settings for the Apple identity provider.
type Config struct {
	// ClientID is the Services ID configured for Sign in with Apple (e.g.,
	// "com.example.web"). Required.
	ClientID string
	// TeamID is the 10-character Apple Developer team identifier. Required.
	TeamID string
	// KeyID is the identifier of the private key registered for Sign in
	// with Apple. Required.
	KeyID string
	// PrivateKey is the PEM-encoded PKCS#8 private key downloaded from the
	// Apple Developer portal (the AuthKey_<KeyID>.p8 file). Required.
	PrivateKey []byte
	// RedirectURI is the absolute URL of the authorization server's external
	// callback endpoint registered with Apple. Required.
	RedirectURI string
	// Scopes overrides the requested scopes. Defaults to "name email".
	// When at least one scope is requested, Apple mandates the form_post
	// response mode.
	Scopes []string
	// Client overrides the HTTP client used for outbound requests to
	// Apple. Defaults to [transport.DefaultClient].
	Client *http.Client
}
