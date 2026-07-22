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

package google

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/deep-rent/nexus/dat/cache"
	"github.com/deep-rent/nexus/net/transport"
	"github.com/deep-rent/nexus/sec/iam/idp"
	"github.com/deep-rent/nexus/sec/iam/idp/oidc"
	"github.com/deep-rent/nexus/sec/jose/jwk"
	"github.com/deep-rent/nexus/sec/jose/jwt"
)

// Google OIDC endpoints, as published at
// https://accounts.google.com/.well-known/openid-configuration.
const (
	AuthEndpoint  = "https://accounts.google.com/o/oauth2/v2/auth"
	TokenEndpoint = "https://oauth2.googleapis.com/token"
	KeySetURL     = "https://www.googleapis.com/oauth2/v3/certs"
)

// Issuers lists the values Google uses for the "iss" claim.
var Issuers = []string{"https://accounts.google.com", "accounts.google.com"}

// DefaultScopes requests the standard OIDC identity profile.
var DefaultScopes = []string{"openid", "email", "profile"}

// Config carries the settings for the Google identity provider.
type Config struct {
	// ClientID is the OAuth 2.0 client ID issued by the Google Cloud
	// console. Required.
	ClientID string
	// ClientSecret is the client secret paired with ClientID. Required.
	ClientSecret string
	// RedirectURI is the absolute URL of the authorization server's external
	// callback endpoint registered with Google. Required.
	RedirectURI string
	// Scopes overrides the requested scopes. Defaults to
	// "openid email profile".
	Scopes []string
	// Client overrides the HTTP client used for outbound requests to
	// Google. Defaults to [transport.DefaultClient].
	Client *http.Client
}

// Provider implements [idp.Provider] for Google.
type Provider struct {
	clientID     string
	clientSecret string
	redirectURI  string
	scopes       []string
	client       *http.Client
	keys         jwk.CacheSet
	verifier     jwt.Verifier[*oidc.IDToken]
	auth         string
	token        string
}

// New assembles a Google [Provider] from the given configuration.
//
// It panics if a required [Config] field is missing; provider construction
// happens once at startup, so misconfiguration is a programmer error.
// Remember to dispatch [Provider.Keys] to a scheduler so that ID token
// verification has fresh signing keys available.
func New(cfg Config) *Provider {
	switch {
	case cfg.ClientID == "":
		panic("client ID is required")
	case cfg.ClientSecret == "":
		panic("client secret is required")
	case cfg.RedirectURI == "":
		panic("redirect URI is required")
	}

	client := cfg.Client
	if client == nil {
		client = transport.DefaultClient
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = DefaultScopes
	}

	keys := jwk.NewCacheSet(KeySetURL, cache.WithClient(client))

	return &Provider{
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		redirectURI:  cfg.RedirectURI,
		scopes:       scopes,
		client:       client,
		keys:         keys,
		verifier: jwt.NewVerifier[*oidc.IDToken](
			keys,
			jwt.WithIssuers(Issuers...),
			jwt.WithAudiences(cfg.ClientID),
			jwt.WithLeeway(time.Minute),
		),
		auth:  AuthEndpoint,
		token: TokenEndpoint,
	}
}

// Keys returns the cached view of Google's remote JWKS used for ID token
// verification.
//
// The returned set implements [github.com/deep-rent/nexus/schedule.Tick];
// dispatch it to a scheduler so the keys are fetched and periodically
// refreshed in the background:
//
//	s := schedule.New(ctx)
//	s.Dispatch(p.Keys())
//
// Until the first successful fetch completes, ID token verification fails
// with [jwt.ErrKeyNotFound]; block on the set's Ready channel during
// startup to guarantee keys are available before serving logins:
//
//	<-p.Keys().Ready()
func (p *Provider) Keys() jwk.CacheSet { return p.keys }

// AuthURL implements [idp.Provider].
func (p *Provider) AuthURL(_ context.Context, state string) (string, error) {
	q := url.Values{
		"client_id":     {p.clientID},
		"redirect_uri":  {p.redirectURI},
		"response_type": {"code"},
		"scope":         {strings.Join(p.scopes, " ")},
		"state":         {state},
	}
	return p.auth + "?" + q.Encode(), nil
}

// Exchange implements [idp.Provider].
//
// It exchanges the authorization code from the callback request for an ID
// token, verifies the token against Google's signing keys, and extracts the
// user's identity.
func (p *Provider) Exchange(
	ctx context.Context,
	req *http.Request,
) (idp.Claimant, error) {
	claims, err := oidc.Callback(ctx, p.client, p.token, req, url.Values{
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
	}, p.redirectURI, p.verifier)
	if err != nil {
		return idp.Claimant{}, err
	}
	return claims.Claimant(), nil
}

var _ idp.Provider = (*Provider)(nil)
