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
	"log/slog"
	"time"

	"github.com/deep-rent/nexus/vault"
)

type Server struct {
	grants               map[GrantType]Grant
	idps                 map[string]IdentityProvider
	vault                vault.Vault
	clients              ClientStore
	sessions             SessionStore
	subjects             SubjectStore
	issuer               string
	sessionCookieName    string
	stateCookieName      string
	accessTokenLifetime  time.Duration
	refreshTokenLifetime time.Duration
	authCodeLifetime     time.Duration
	deviceCodeLifetime   time.Duration
	realm                string
	loginTerminalURI     string
	loginRedirectURI     string
	generateSessionKey   TokenGeneratorFn
	generateAuthCode     TokenGeneratorFn
	generateRefreshToken TokenGeneratorFn
	generateDeviceCode   TokenGeneratorFn
	generateUserCode     TokenGeneratorFn
	generateState        TokenGeneratorFn
	verificationURI      string
	logger               *slog.Logger
	clock                func() time.Time
}
