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
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/deep-rent/nexus/oauth"
)

const (
	DefaultAuthURL     = "https://accounts.google.com/o/oauth2/v2/auth"
	DefaultTokenURL    = "https://oauth2.googleapis.com/token"
	DefaultUserInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
)

// Config holds the configuration for the Google identity provider.
type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       []string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
}

// Google implements the [oauth.IdentityProvider] interface for Google login.
type Google struct {
	cfg    Config
	client *http.Client
}

// New creates a new Google identity provider with an optimized HTTP client.
//
// If no scopes are provided, it defaults to standard OpenID Connect scopes
// ("openid", "email", "profile").
func New(c Config) *Google {
	if len(c.Scopes) == 0 {
		c.Scopes = []string{"openid", "email", "profile"}
	}
	if c.AuthURL == "" {
		c.AuthURL = DefaultAuthURL
	}
	if c.TokenURL == "" {
		c.TokenURL = DefaultTokenURL
	}
	if c.UserInfoURL == "" {
		c.UserInfoURL = DefaultUserInfoURL
	}

	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 100
	t.MaxIdleConnsPerHost = 100
	t.IdleConnTimeout = 90 * time.Second

	return &Google{
		cfg: c,
		client: &http.Client{
			Timeout:   10 * time.Second,
			Transport: t,
		},
	}
}

// AuthURL implements [oauth.IdentityProvider].
func (g *Google) AuthURL(ctx context.Context, state string) (string, error) {
	u, err := url.Parse(g.cfg.AuthURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("client_id", g.cfg.ClientID)
	q.Set("redirect_uri", g.cfg.RedirectURI)
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(g.cfg.Scopes, " "))
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

func (g *Google) exchange(ctx context.Context, code string) (string, error) {
	data := url.Values{}
	data.Set("client_id", g.cfg.ClientID)
	data.Set("client_secret", g.cfg.ClientSecret)
	data.Set("redirect_uri", g.cfg.RedirectURI)
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		g.cfg.TokenURL,
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
	defer func() {
		_ = res.Body.Close()
	}()

	if code := res.StatusCode; code != http.StatusOK {
		return "", fmt.Errorf("token exchange returned status %d", code)
	}

	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.UnmarshalRead(res.Body, &body); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	return body.AccessToken, nil
}

func (g *Google) userInfo(
	ctx context.Context,
	token string,
) (oauth.ExternalIdentity, error) {
	var eid oauth.ExternalIdentity
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		g.cfg.UserInfoURL,
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
	defer func() {
		_ = res.Body.Close()
	}()

	if code := res.StatusCode; code != http.StatusOK {
		return eid, fmt.Errorf("userinfo returned status %d", code)
	}

	if err := json.UnmarshalRead(res.Body, &eid); err != nil {
		return eid, fmt.Errorf("decode userinfo response: %w", err)
	}

	return eid, nil
}
