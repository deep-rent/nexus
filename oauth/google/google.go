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

// Package google provides a Google identity provider implementation for OAuth2.
//
// This package implements the [oauth.IdentityProvider] interface to facilitate
// social login using Google's OpenID Connect (OIDC) endpoints. It handles the
// generation of authorization URLs, the exchange of authorization codes for
// access tokens, and the retrieval of user identity information.
//
// # Usage
//
// To use the Google provider, initialize it with a [Config] and register it
// with your OAuth manager.
//
// Example:
//
//	provider := google.New(google.Config{
//		ClientID:     "your-client-id",
//		ClientSecret: "your-client-secret",
//		RedirectURI:  "https://example.com/callback",
//	})
//
//	// Generate the redirect URL for the user.
//	url, _ := provider.AuthURL(ctx, "state-token")
package google

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/deep-rent/nexus/oauth"
)

const (
	// DefaultAuthURL is the default Google OAuth 2.0 authorization endpoint.
	DefaultAuthURL = "https://accounts.google.com/o/oauth2/v2/auth"
	// DefaultTokenURL is the default Google OAuth 2.0 token exchange endpoint.
	DefaultTokenURL = "https://oauth2.googleapis.com/token"
	// DefaultUserInfoURL is the default OpenID Connect userinfo endpoint.
	DefaultUserInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
	// DefaultTimeout is the default duration for network requests.
	DefaultTimeout = 5 * time.Second
)

// DefaultScopes contains the standard OIDC scopes used if none are specified.
var DefaultScopes = []string{"openid", "email", "profile"}

const maxBodySize = 1 << 16 // 64 KB

// Config holds the configuration for the Google identity provider.
type Config struct {
	// ClientID is the public identifier for the application.
	// This option is mandatory.
	ClientID string
	// ClientSecret is the secret shared between the app and Google.
	// This option is mandatory.
	ClientSecret string
	// RedirectURI is the URL where Google will send the authorization code.
	// This option is mandatory.
	RedirectURI string
	// Scopes defines the permissions requested from the user.
	// Defaults to [DefaultScopes].
	Scopes []string
	// AuthURL allows overriding the default authorization endpoint.
	// Defaults to [DefaultAuthURL].
	AuthURL string
	// TokenURL allows overriding the default token exchange endpoint.
	// Defaults to [DefaultTokenURL].
	TokenURL string
	// UserInfoURL allows overriding the default identity retrieval endpoint.
	// Defaults to [DefaultUserInfoURL].
	UserInfoURL string
	// Timeout sets the maximum duration for identity provider network calls.
	// Defaults to [DefaultTimeout].
	Timeout time.Duration
}

// Google implements the [oauth.IdentityProvider] interface for Google login.
type Google struct {
	clientID     string
	clientSecret string
	redirectURI  string
	scope        string
	authURL      *url.URL
	tokenURL     string
	userInfoURL  string
	client       *http.Client
}

var _ oauth.IdentityProvider = (*Google)(nil)

// New creates a new Google identity provider with an optimized HTTP client.
//
// If no scopes are provided, it defaults to standard OpenID Connect scopes
// ("openid", "email", "profile"). It panics if options are missing or invalid.
func New(cfg Config) *Google {
	g := &Google{}

	if clientID := cfg.ClientID; clientID == "" {
		panic("google: missing client ID")
	} else {
		g.clientID = clientID
	}

	if clientSecret := cfg.ClientSecret; clientSecret == "" {
		panic("google: missing client secret")
	} else {
		g.clientSecret = clientSecret
	}

	if redirectURI := cfg.RedirectURI; redirectURI == "" {
		panic("google: missing redirect URI")
	} else {
		g.redirectURI = redirectURI
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = DefaultScopes
	}
	g.scope = strings.Join(scopes, " ")

	authURL := cfg.AuthURL
	if authURL == "" {
		authURL = DefaultAuthURL
	}
	if u, err := url.Parse(authURL); err != nil {
		panic("google: invalid auth URL")
	} else {
		g.authURL = u
	}

	tokenURL := cfg.TokenURL
	if tokenURL == "" {
		tokenURL = DefaultTokenURL
	}
	if _, err := url.Parse(tokenURL); err != nil {
		panic("google: invalid token URL")
	} else {
		g.tokenURL = tokenURL
	}

	userInfoURL := cfg.UserInfoURL
	if userInfoURL == "" {
		userInfoURL = DefaultUserInfoURL
	}
	if _, err := url.Parse(userInfoURL); err != nil {
		panic("google: invalid userinfo URL")
	} else {
		g.userInfoURL = userInfoURL
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	// t defines a transport with aggressive timeouts for high availability.
	t := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout: timeout / 3,
		}).DialContext,
		TLSHandshakeTimeout:   timeout / 3,
		ResponseHeaderTimeout: timeout * 9 / 10,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
	}

	g.client = &http.Client{
		Timeout:   timeout,
		Transport: t,
	}
	return g
}

// AuthURL implements [oauth.IdentityProvider].
func (g *Google) AuthURL(ctx context.Context, state string) (string, error) {
	u := *g.authURL // Create a shallow copy to ensure thread-safety

	q := u.Query()
	q.Set("client_id", g.clientID)
	q.Set("redirect_uri", g.redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", g.scope)
	q.Set("state", state)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// Process implements [oauth.IdentityProvider].
func (g *Google) Process(
	ctx context.Context,
	req *http.Request,
) (oauth.ExternalIdentity, error) {
	q := req.URL.Query()

	// Check if Google returned an error string in the query parameters.
	if desc := q.Get("error"); desc != "" {
		err := fmt.Errorf("google auth error: %s", desc)
		return oauth.ExternalIdentity{}, err
	}

	code := q.Get("code")
	if code == "" {
		err := errors.New("missing authorization code in callback")
		return oauth.ExternalIdentity{}, err
	}

	accessToken, err := g.exchange(ctx, code)
	if err != nil {
		return oauth.ExternalIdentity{}, err
	}

	identity, err := g.userInfo(ctx, accessToken)
	if err != nil {
		return oauth.ExternalIdentity{}, err
	}

	if identity.Subject == "" {
		err := errors.New("missing subject in userinfo response")
		return oauth.ExternalIdentity{}, err
	}

	return identity, nil
}

// exchange swaps the authorization code for a bearer access token.
func (g *Google) exchange(ctx context.Context, code string) (string, error) {
	data := url.Values{}
	data.Set("client_id", g.clientID)
	data.Set("client_secret", g.clientSecret)
	data.Set("redirect_uri", g.redirectURI)
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		g.tokenURL,
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return "", fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// Execute the token exchange request.
	res, err := g.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("execute token request: %w", err)
	}

	r := io.LimitReader(res.Body, maxBodySize)
	defer func() {
		// Exhaust the reader and close the body to enable keep-alive.
		_, _ = io.Copy(io.Discard, r)
		_ = res.Body.Close()
	}()

	if code := res.StatusCode; code != http.StatusOK {
		return "", fmt.Errorf("token exchange returned status %d", code)
	}

	var body struct {
		AccessToken string `json:"access_token"`
	}

	if err := json.UnmarshalRead(r, &body); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	return body.AccessToken, nil
}

// userInfo fetches the identity claims from the Google UserInfo endpoint.
func (g *Google) userInfo(
	ctx context.Context,
	token string,
) (oauth.ExternalIdentity, error) {
	var eid oauth.ExternalIdentity
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		g.userInfoURL,
		nil,
	)
	if err != nil {
		return eid, fmt.Errorf("create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	res, err := g.client.Do(req)
	if err != nil {
		return eid, fmt.Errorf("execute userinfo request: %w", err)
	}

	r := io.LimitReader(res.Body, maxBodySize)
	defer func() {
		// Exhaust the reader and close the body to enable keep-alive.
		_, _ = io.Copy(io.Discard, r)
		_ = res.Body.Close()
	}()

	if code := res.StatusCode; code != http.StatusOK {
		return eid, fmt.Errorf("userinfo returned status %d", code)
	}

	if err := json.UnmarshalRead(r, &eid); err != nil {
		return eid, fmt.Errorf("decode userinfo response: %w", err)
	}

	return eid, nil
}
