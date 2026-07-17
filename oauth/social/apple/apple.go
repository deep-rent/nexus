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
//	p, err := apple.New(apple.Config{
//	  ClientID:    "com.example.web",     // Services ID
//	  TeamID:      "94Z27KF87Q",
//	  KeyID:       "3JD9C6QQ7A",
//	  PrivateKey:  keyPEM,                // contents of AuthKey_XXX.p8
//	  RedirectURI: "https://id.example.com/oauth/callback/apple",
//	})
//	if err != nil { /* handle configuration error */ }
//
//	// Keep Apple's signing keys fresh in the background.
//	scheduler.Dispatch(p.Keys())
//
//	s, err := oauth.New(cfg, oauth.WithIdentityProvider("apple", p))
package apple

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/oauth"
	"github.com/deep-rent/nexus/oauth/social"
	"github.com/deep-rent/nexus/sign"
)

// Apple endpoints and token issuer, as documented at
// https://developer.apple.com/documentation/signinwithapple.
const (
	authEndpoint  = "https://appleid.apple.com/auth/authorize"
	tokenEndpoint = "https://appleid.apple.com/auth/token"
	keySetURL     = "https://appleid.apple.com/auth/keys"
	issuer        = "https://appleid.apple.com"
)

// secretLifetime bounds the validity of the self-signed client secret JWT.
// Apple allows up to six months; a short window suffices since the secret
// is minted per exchange.
const secretLifetime = 5 * time.Minute

// defaultScopes requests the user's name and email on first authorization.
var defaultScopes = []string{"name", "email"}

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
	// Apple. Defaults to a client bounded by [social.DefaultTimeout].
	Client *http.Client
}

// Provider implements [oauth.IdentityProvider] for Apple.
type Provider struct {
	clientID    string
	teamID      string
	redirectURI string
	scopes      []string
	key         jwk.KeyPair
	client      *http.Client
	keys        jwk.CacheSet
	verifier    jwt.Verifier[*social.IDToken]
	auth        string
	token       string
	now         func() time.Time
}

// New assembles an Apple [Provider] from the given configuration.
//
// It returns an error if a required [Config] field is missing or if the
// private key cannot be parsed as an ES256-capable PKCS#8 key. Remember to
// dispatch [Provider.Keys] to a scheduler so that ID token verification has
// fresh signing keys available.
func New(cfg Config) (*Provider, error) {
	switch {
	case cfg.ClientID == "":
		return nil, errors.New("apple: Config.ClientID is required")
	case cfg.TeamID == "":
		return nil, errors.New("apple: Config.TeamID is required")
	case cfg.KeyID == "":
		return nil, errors.New("apple: Config.KeyID is required")
	case len(cfg.PrivateKey) == 0:
		return nil, errors.New("apple: Config.PrivateKey is required")
	case cfg.RedirectURI == "":
		return nil, errors.New("apple: Config.RedirectURI is required")
	}

	key, err := parseKey(cfg.PrivateKey, cfg.KeyID)
	if err != nil {
		return nil, err
	}

	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: social.DefaultTimeout}
	}

	scopes := cfg.Scopes
	if scopes == nil {
		scopes = defaultScopes
	}

	keys := jwk.NewCacheSet(client, keySetURL)

	return &Provider{
		clientID:    cfg.ClientID,
		teamID:      cfg.TeamID,
		redirectURI: cfg.RedirectURI,
		scopes:      scopes,
		key:         key,
		client:      client,
		keys:        keys,
		verifier: jwt.NewVerifier[*social.IDToken](
			keys,
			jwt.WithIssuers(issuer),
			jwt.WithAudiences(cfg.ClientID),
			jwt.WithLeeway(time.Minute),
		),
		auth:  authEndpoint,
		token: tokenEndpoint,
		now:   time.Now,
	}, nil
}

// parseKey decodes the PEM-encoded PKCS#8 private key and wraps it into an
// ES256 signing key pair carrying the given key ID.
func parseKey(pemBytes []byte, kid string) (jwk.KeyPair, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New(
			"apple: Config.PrivateKey is not PEM encoded",
		)
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf(
			"apple: failed to parse Config.PrivateKey: %w",
			err,
		)
	}

	ec, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New(
			"apple: Config.PrivateKey is not an ECDSA key",
		)
	}

	key := jwk.NewKeyPair(jwa.ES256, kid, sign.From(ec))
	if key == nil {
		return nil, errors.New(
			"apple: Config.PrivateKey is not usable for ES256 signing",
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
// with [jwt.ErrKeyNotFound].
func (p *Provider) Keys() jwk.CacheSet { return p.keys }

// AuthURL implements [oauth.IdentityProvider].
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
		Exp: now.Add(secretLifetime),
		Aud: issuer,
		Sub: p.clientID,
	})
	if err != nil {
		return "", fmt.Errorf("apple: failed to sign client secret: %w", err)
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
	Email string `json:"email"`
}

// Process implements [oauth.IdentityProvider].
//
// It exchanges the authorization code from the callback request for an ID
// token, verifies the token against Apple's signing keys, and extracts the
// user's identity. On the subject's first authorization, the display name
// from the accompanying "user" payload is merged into the result.
func (p *Provider) Process(
	ctx context.Context,
	req *http.Request,
) (oauth.Claimant, error) {
	if e := req.FormValue("error"); e != "" {
		return oauth.Claimant{}, fmt.Errorf(
			"apple: authorization failed: %s",
			e,
		)
	}

	code := req.FormValue("code")
	if code == "" {
		return oauth.Claimant{}, errors.New(
			"apple: missing authorization code",
		)
	}

	secret, err := p.clientSecret(ctx)
	if err != nil {
		return oauth.Claimant{}, err
	}

	tok, err := social.Exchange(ctx, p.client, p.token, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {p.clientID},
		"client_secret": {secret},
		"redirect_uri":  {p.redirectURI},
	})
	if err != nil {
		return oauth.Claimant{}, fmt.Errorf("apple: %w", err)
	}

	if tok.IDToken == "" {
		return oauth.Claimant{}, errors.New(
			"apple: token response is missing the id_token",
		)
	}

	claims, err := p.verifier.Verify([]byte(tok.IDToken))
	if err != nil {
		return oauth.Claimant{}, fmt.Errorf(
			"apple: id token verification failed: %w",
			err,
		)
	}

	claimant := claims.Claimant()

	// Apple shares the user's name only once, in the "user" form field of
	// the very first callback; it never appears in the ID token.
	if raw := req.FormValue("user"); raw != "" {
		var u user
		if err := json.Unmarshal([]byte(raw), &u); err == nil {
			name := strings.TrimSpace(
				u.Name.FirstName + " " + u.Name.LastName,
			)
			if claimant.Name == "" {
				claimant.Name = name
			}
			if claimant.Email == "" {
				claimant.Email = u.Email
			}
		}
	}

	return claimant, nil
}

var _ oauth.IdentityProvider = (*Provider)(nil)
