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
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/deep-rent/nexus/dat/cache"
	"github.com/deep-rent/nexus/net/transport"
	"github.com/deep-rent/nexus/sec/iam/idp"
	"github.com/deep-rent/nexus/sec/iam/idp/oidc"
	"github.com/deep-rent/nexus/sec/jose/jwa"
	"github.com/deep-rent/nexus/sec/jose/jwk"
	"github.com/deep-rent/nexus/sec/jose/jwt"
	"github.com/deep-rent/nexus/sec/sign"
)

// Apple endpoints and token Issuer, as documented at
// https://developer.apple.com/documentation/signinwithapple.
const (
	AuthEndpoint  = "https://appleid.apple.com/auth/authorize"
	TokenEndpoint = "https://appleid.apple.com/auth/token"
	KeySetURL     = "https://appleid.apple.com/auth/keys"
	Issuer        = "https://appleid.apple.com"
)

// SecretLifetime bounds the validity of the self-signed client secret JWT.
// Apple allows up to six months; a short window suffices since the secret
// is minted per exchange.
const SecretLifetime = 5 * time.Minute

// DefaultScopes requests the user's name and email on first authorization.
var DefaultScopes = []string{"name", "email"}

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

// Provider implements [idp.Provider] for Apple.
type Provider struct {
	clientID    string
	teamID      string
	redirectURI string
	scopes      []string
	key         jwk.KeyPair
	client      *http.Client
	keys        jwk.CacheSet
	verifier    jwt.Verifier[*oidc.IDToken]
	auth        string
	token       string
	now         func() time.Time
}

// New assembles an Apple [Provider] from the given configuration.
//
// It panics if a required [Config] field is missing or if the private key
// cannot be parsed as an ES256-capable PKCS#8 key; provider construction
// happens once at startup, so misconfiguration is a programmer error.
// Remember to dispatch [Provider.Keys] to a scheduler so that ID token
// verification has fresh signing keys available.
func New(cfg Config) *Provider {
	switch {
	case cfg.ClientID == "":
		panic("client ID is required")
	case cfg.TeamID == "":
		panic("team ID is required")
	case cfg.KeyID == "":
		panic("key ID is required")
	case len(cfg.PrivateKey) == 0:
		panic("private key is required")
	case cfg.RedirectURI == "":
		panic("redirect URI is required")
	}

	key, err := parseKey(cfg.PrivateKey, cfg.KeyID)
	if err != nil {
		panic(err.Error())
	}

	client := cfg.Client
	if client == nil {
		client = transport.DefaultClient
	}

	scopes := cfg.Scopes
	if scopes == nil {
		scopes = DefaultScopes
	}

	keys := jwk.NewCacheSet(KeySetURL, cache.WithClient(client))

	return &Provider{
		clientID:    cfg.ClientID,
		teamID:      cfg.TeamID,
		redirectURI: cfg.RedirectURI,
		scopes:      scopes,
		key:         key,
		client:      client,
		keys:        keys,
		verifier: jwt.NewVerifier[*oidc.IDToken](
			keys,
			jwt.WithIssuers(Issuer),
			jwt.WithAudiences(cfg.ClientID),
			jwt.WithLeeway(time.Minute),
		),
		auth:  AuthEndpoint,
		token: TokenEndpoint,
		now:   time.Now,
	}
}

// parseKey decodes the PEM-encoded private key and wraps it into an ES256
// signing key pair carrying the given key ID.
func parseKey(pemBytes []byte, kid string) (jwk.KeyPair, error) {
	signer, err := sign.Decode(pemBytes)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to parse Config.PrivateKey: %w",
			err,
		)
	}

	key := jwk.NewKeyPair(jwa.ES256, kid, signer)
	if key == nil {
		return nil, errors.New(
			"Config.PrivateKey is not usable for ES256 signing",
		)
	}
	return key, nil
}

// Keys returns the cached view of Apple's remote JWKS used for ID token
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
		"state":         {state},
	}
	if len(p.scopes) > 0 {
		q.Set("scope", strings.Join(p.scopes, " "))
		// Apple mandates the form_post response mode whenever scopes are
		// requested. The callback then arrives as a cross-site POST.
		q.Set("response_mode", "form_post")
	}
	return p.auth + "?" + q.Encode(), nil
}

// secretClaims is the payload of the self-signed client secret JWT.
type secretClaims struct {
	Iss string    `json:"iss"`
	Iat time.Time `json:"iat"`
	Exp time.Time `json:"exp"`
	Aud string    `json:"aud"`
	Sub string    `json:"sub"`
}

// clientSecret mints the short-lived ES256 JWT that authenticates the
// provider against Apple's token endpoint.
func (p *Provider) clientSecret(ctx context.Context) (string, error) {
	now := p.now()
	token, err := jwt.Sign(ctx, p.key, secretClaims{
		Iss: p.teamID,
		Iat: now,
		Exp: now.Add(SecretLifetime),
		Aud: Issuer,
		Sub: p.clientID,
	})
	if err != nil {
		return "", fmt.Errorf("failed to sign client secret: %w", err)
	}
	return string(token), nil
}

// user models the one-time "user" JSON payload Apple posts alongside the
// first authorization of a subject.
type user struct {
	Name struct {
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	} `json:"name"`
}

// Exchange implements [idp.Provider].
//
// It exchanges the authorization code from the callback request for an ID
// token, verifies the token against Apple's signing keys, and extracts the
// user's identity. On the subject's first authorization, the display name
// from the accompanying "user" payload is merged into the result.
func (p *Provider) Exchange(
	ctx context.Context,
	req *http.Request,
) (idp.Claimant, error) {
	secret, err := p.clientSecret(ctx)
	if err != nil {
		return idp.Claimant{}, err
	}

	claims, err := oidc.Callback(ctx, p.client, p.token, req, url.Values{
		"client_id":     {p.clientID},
		"client_secret": {secret},
	}, p.redirectURI, p.verifier)
	if err != nil {
		return idp.Claimant{}, err
	}

	claimant := claims.Claimant()

	// Apple shares the user's name only once, in the "user" form field of
	// the very first callback; it never appears in the ID token. The payload
	// is unauthenticated form data from the user-agent, so only display
	// metadata is merged — identity claims such as the email must come from
	// the verified ID token.
	if raw := req.FormValue("user"); raw != "" && claimant.Name == "" {
		var u user
		if err := json.Unmarshal([]byte(raw), &u); err == nil {
			claimant.Name = strings.TrimSpace(
				u.Name.FirstName + " " + u.Name.LastName,
			)
		}
	}

	return claimant, nil
}

var _ idp.Provider = (*Provider)(nil)
