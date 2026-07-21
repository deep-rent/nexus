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

package oidc

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/oauth"
)

// Boolish is a bool that additionally accepts the JSON string forms "true"
// and "false". Some providers (notably Apple) encode boolean claims such as
// email_verified as strings.
type Boolish bool

// UnmarshalJSON parses both native and stringified boolean values.
func (b *Boolish) UnmarshalJSON(data []byte) error {
	v, err := strconv.ParseBool(strings.Trim(string(data), `"`))
	if err != nil {
		return fmt.Errorf("expected a boolean value: %w", err)
	}
	*b = Boolish(v)
	return nil
}

// IDToken models the claims of an OIDC ID token issued by an external
// provider. It implements [jwt.Claims] so it can be validated with a
// [jwt.Verifier].
type IDToken struct {
	// Jti is the unique token identifier, if the provider issues one.
	Jti string `json:"jti,omitempty"`
	// Sub is the provider-scoped unique identifier of the user.
	Sub string `json:"sub"`
	// Iss identifies the token issuer.
	Iss string `json:"iss,omitempty"`
	// Aud lists the intended token audiences, usually the client ID.
	Aud jwt.Audience `json:"aud,omitempty"`
	// Iat is the time the token was issued.
	Iat time.Time `json:"iat,omitzero"`
	// Exp is the token expiry time.
	Exp time.Time `json:"exp,omitzero"`
	// Nbf is the time before which the token must be rejected.
	Nbf time.Time `json:"nbf,omitzero"`
	// Email is the user's email address at the provider.
	Email string `json:"email,omitempty"`
	// EmailVerified indicates whether the provider verified the email.
	EmailVerified Boolish `json:"email_verified,omitzero"`
	// Name is the user's display name, if the provider shares one.
	Name string `json:"name,omitempty"`
	// Picture is the URL of the user's profile picture, if shared.
	Picture string `json:"picture,omitempty"`
}

// ID implements [jwt.Claims].
func (t *IDToken) ID() string { return t.Jti }

// Subject implements [jwt.Claims].
func (t *IDToken) Subject() string { return t.Sub }

// Issuer implements [jwt.Claims].
func (t *IDToken) Issuer() string { return t.Iss }

// Audience implements [jwt.Claims].
func (t *IDToken) Audience() []string { return t.Aud }

// IssuedAt implements [jwt.Claims].
func (t *IDToken) IssuedAt() time.Time { return t.Iat }

// ExpiresAt implements [jwt.Claims].
func (t *IDToken) ExpiresAt() time.Time { return t.Exp }

// NotBefore implements [jwt.Claims].
func (t *IDToken) NotBefore() time.Time { return t.Nbf }

var _ jwt.Claims = (*IDToken)(nil)

// Claimant converts the verified ID token into the [oauth.Claimant] shape
// consumed by the authorization server.
func (t *IDToken) Claimant() oauth.Claimant {
	return oauth.Claimant{
		Subject:       t.Sub,
		Email:         t.Email,
		EmailVerified: bool(t.EmailVerified),
		Name:          t.Name,
		Picture:       t.Picture,
	}
}

// Exchange posts the given form to a provider's token endpoint and decodes
// the JSON response into an [oauth.TokenResponse].
//
// Non-200 responses are converted into descriptive errors, surfacing the
// provider's "error" and "error_description" fields when present.
func Exchange(
	ctx context.Context,
	client *http.Client,
	endpoint string,
	form url.Values,
) (oauth.TokenResponse, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return oauth.TokenResponse{}, fmt.Errorf(
			"failed to build token request: %w",
			err,
		)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return oauth.TokenResponse{}, fmt.Errorf(
			"token request failed: %w",
			err,
		)
	}
	defer func() {
		_ = res.Body.Close()
	}()

	// The client caps response body size, so this read is bounded.
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return oauth.TokenResponse{}, fmt.Errorf(
			"failed to read token response: %w",
			err,
		)
	}

	if res.StatusCode != http.StatusOK {
		var e oauth.Error
		if err := json.Unmarshal(body, &e); err == nil && e.Code != "" {
			if e.Description != "" {
				return oauth.TokenResponse{}, fmt.Errorf(
					"token endpoint returned %q: %s",
					e.Code,
					e.Description,
				)
			}
			return oauth.TokenResponse{}, fmt.Errorf(
				"token endpoint returned %q",
				e.Code,
			)
		}
		return oauth.TokenResponse{}, fmt.Errorf(
			"token endpoint returned status %d",
			res.StatusCode,
		)
	}

	var tok oauth.TokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return oauth.TokenResponse{}, fmt.Errorf(
			"failed to decode token response: %w",
			err,
		)
	}
	return tok, nil
}

// Callback drives the relying-party callback pipeline shared by all
// providers: it validates the authorization response parameters carried by
// req (covering both query and form_post response modes), exchanges the
// authorization code at the provider's token endpoint, and verifies the
// returned ID token.
//
// The form must already contain the provider's client credentials
// (client_id plus client_secret or equivalent); Callback fills in
// grant_type, code, and redirect_uri.
func Callback(
	ctx context.Context,
	client *http.Client,
	endpoint string,
	req *http.Request,
	form url.Values,
	redirectURI string,
	verifier jwt.Verifier[*IDToken],
) (*IDToken, error) {
	if e := req.FormValue("error"); e != "" {
		return nil, fmt.Errorf("authorization failed: %s", e)
	}

	code := req.FormValue("code")
	if code == "" {
		return nil, errors.New("missing authorization code")
	}

	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)

	tok, err := Exchange(ctx, client, endpoint, form)
	if err != nil {
		return nil, err
	}

	if tok.IDToken == "" {
		return nil, errors.New("token response is missing the id_token")
	}

	claims, err := verifier.Verify([]byte(tok.IDToken))
	if err != nil {
		return nil, fmt.Errorf("id token verification failed: %w", err)
	}
	return claims, nil
}
