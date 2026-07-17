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
// [oauth.IdentityProvider].
//
// The provider drives the OIDC Authorization Code flow against Google's
// endpoints: it redirects the user-agent to Google's consent screen,
// exchanges the returned authorization code for an ID token, and verifies
// that token against Google's published JWKS.
//
// # Usage
//
//	p, err := google.New(google.Config{
//	  ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
//	  ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
//	  RedirectURI:  "https://id.example.com/oauth/callback/google",
//	})
//	if err != nil { /* handle configuration error */ }
//
//	// Keep Google's signing keys fresh in the background.
//	scheduler.Dispatch(p.Keys())
//
//	s, err := oauth.New(cfg, oauth.WithIdentityProvider("google", p))
package google

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/oauth"
	"github.com/deep-rent/nexus/oauth/oidc"
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
	// Google. Defaults to a client bounded by [oidc.DefaultTimeout].
	Client *http.Client
}

// Provider implements [oauth.IdentityProvider] for Google.
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
// It returns an error if a required [Config] field is missing. Remember to
// dispatch [Provider.Keys] to a scheduler so that ID token verification has
// fresh signing keys available.
func New(cfg Config) (*Provider, error) {
	switch {
	case cfg.ClientID == "":
		return nil, errors.New("Config.ClientID is required")
	case cfg.ClientSecret == "":
		return nil, errors.New("Config.ClientSecret is required")
	case cfg.RedirectURI == "":
		return nil, errors.New("Config.RedirectURI is required")
	}

	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: oidc.DefaultTimeout}
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = DefaultScopes
	}

	keys := jwk.NewCacheSet(client, KeySetURL)

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
	}, nil
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
// with [jwt.ErrKeyNotFound].
func (p *Provider) Keys() jwk.CacheSet { return p.keys }

// AuthURL implements [oauth.IdentityProvider].
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

// Exchange implements [oauth.IdentityProvider].
//
// It exchanges the authorization code from the callback request for an ID
// token, verifies the token against Google's signing keys, and extracts the
// user's identity.
func (p *Provider) Exchange(
	ctx context.Context,
	req *http.Request,
) (oauth.Claimant, error) {
	if e := req.FormValue("error"); e != "" {
		return oauth.Claimant{}, fmt.Errorf(
			"authorization failed: %s",
			e,
		)
	}

	code := req.FormValue("code")
	if code == "" {
		return oauth.Claimant{}, errors.New(
			"missing authorization code",
		)
	}

	tok, err := oidc.Exchange(ctx, p.client, p.token, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
		"redirect_uri":  {p.redirectURI},
	})
	if err != nil {
		return oauth.Claimant{}, err
	}

	if tok.IDToken == "" {
		return oauth.Claimant{}, errors.New(
			"token response is missing the id_token",
		)
	}

	claims, err := p.verifier.Verify([]byte(tok.IDToken))
	if err != nil {
		return oauth.Claimant{}, fmt.Errorf(
			"id token verification failed: %w",
			err,
		)
	}

	return claims.Claimant(), nil
}

var _ oauth.IdentityProvider = (*Provider)(nil)
