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

// Package fcm provides a Firebase Cloud Messaging (FCM) v1 provider.
//
// It implements the [push.Sender] interface for delivering remote
// notifications to Android devices using OAuth 2.0 authentication.
//
// # Usage
//
// Create a sender by providing the raw contents of your Google Service Account
// JSON credentials file.
//
//	sender := fcm.New(
//		http.DefaultClient,
//		credentials, // Google Service Account JSON
//	)
//	err := sender.Send(ctx, msg)
package fcm

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/push"
	"github.com/deep-rent/nexus/sign"
	"github.com/deep-rent/nexus/token"
)

const (
	// DefaultScope is the default scope for FCM v1 API.
	DefaultScope = "https://www.googleapis.com/auth/firebase.messaging"
	// DefaultBaseURL is the default base URL for FCM v1 API.
	DefaultBaseURL = "https://fcm.googleapis.com/v1"
	// DefaultAuthURL is the default authentication URL for FCM v1 API.
	DefaultAuthURL = "https://oauth2.googleapis.com/token"
)

// Sender implements the [push.Sender] interface for Firebase Cloud Messaging
// (FCM). It handles authentication, payload construction, and dispatching of
// push notifications to FCM endpoints.
type Sender struct {
	projectID string
	source    *token.Source
	url       string
	client    *http.Client
	logger    *slog.Logger
	clock     func() time.Time
}

var _ push.Sender = (*Sender)(nil)

type config struct {
	baseURL string
	authURL string
	logger  *slog.Logger
	clock   func() time.Time
}

// Option defines the functional option pattern for configuring the FCM sender.
type Option func(*config)

// WithBaseURL allows overriding the FCM API base URL.
// Useful for mocking. Empty string values are ignored.
func WithBaseURL(url string) Option {
	return func(cfg *config) {
		if url != "" {
			cfg.baseURL = url
		}
	}
}

// WithAuthURL allows overriding the Google OAuth 2.0 token endpoint.
// Useful for mocking. Empty string values are ignored.
func WithAuthURL(url string) Option {
	return func(cfg *config) {
		if url != "" {
			cfg.authURL = url
		}
	}
}

// WithLogger injects a structured [slog.Logger] into the sender.
// Nil values are ignored.
func WithLogger(logger *slog.Logger) Option {
	return func(cfg *config) {
		if logger != nil {
			cfg.logger = logger
		}
	}
}

// WithClock injects a custom clock function for JWT generation and caching.
// Nil values are ignored.
func WithClock(clock func() time.Time) Option {
	return func(cfg *config) {
		if clock != nil {
			cfg.clock = clock
		}
	}
}

// serviceAccount represents the structure of a Google Service Account JSON
// file.
type serviceAccount struct {
	ProjectID   string `json:"project_id"`
	PrivateKey  string `json:"private_key"`
	ClientEmail string `json:"client_email"`
}

// New creates a configured Firebase Cloud Messaging client implementing the
// [push.Sender] interface. It requires the raw contents of the Google Service
// Account JSON credentials file.
func New(
	client *http.Client,
	credentials []byte,
	opts ...Option,
) push.Sender {
	var sa serviceAccount
	if err := json.Unmarshal(credentials, &sa); err != nil {
		panic(fmt.Errorf("failed to parse FCM credentials JSON: %w", err))
	}
	if sa.ProjectID == "" || sa.PrivateKey == "" || sa.ClientEmail == "" {
		panic("credentials JSON is missing required fields")
	}

	signer, err := sign.Decode([]byte(sa.PrivateKey))
	if err != nil {
		panic(fmt.Errorf("failed to parse FCM private key: %w", err))
	}
	var key jwk.KeyPair
	switch signer.Public().(type) {
	case *rsa.PublicKey:
		key = jwk.NewKeyPair(jwa.RS256, "", signer)
	case *ecdsa.PublicKey:
		key = jwk.NewKeyPair(jwa.ES256, "", signer)
	default:
		panic("unsupported private key type for FCM")
	}

	cfg := config{
		baseURL: DefaultBaseURL,
		authURL: DefaultAuthURL,
		logger:  slog.Default(),
		clock:   time.Now,
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	s := &Sender{
		projectID: sa.ProjectID,
		url:       cfg.baseURL,
		logger:    cfg.logger,
		client:    client,
		clock:     cfg.clock,
	}

	fetch := func(ctx context.Context) (string, time.Time, error) {
		claims := struct {
			Iss   string `json:"iss"`
			Scope string `json:"scope"`
			Aud   string `json:"aud"`
			Iat   int64  `json:"iat"`
			Exp   int64  `json:"exp"`
		}{
			Iss:   sa.ClientEmail,
			Scope: DefaultScope,
			Aud:   cfg.authURL,
			Iat:   cfg.clock().Unix(),
			Exp:   cfg.clock().Add(time.Hour).Unix(),
		}

		assertion, err := jwt.Sign(ctx, key, claims)
		if err != nil {
			return "", time.Time{}, fmt.Errorf(
				"failed to sign oauth assertion: %w",
				err,
			)
		}

		data := url.Values{}
		data.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
		data.Set("assertion", string(assertion))

		req, err := http.NewRequestWithContext(
			ctx,
			http.MethodPost,
			cfg.authURL,
			strings.NewReader(data.Encode()),
		)
		if err != nil {
			return "", time.Time{}, fmt.Errorf(
				"failed to create oauth request: %w",
				err,
			)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		res, err := s.client.Do(req)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("oauth request failed: %w", err)
		}
		defer func() {
			if err := res.Body.Close(); err != nil {
				s.logger.Error(
					"failed to close response body",
					slog.Any("error", err),
				)
			}
		}()

		if res.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(res.Body)
			return "", time.Time{}, fmt.Errorf(
				"oauth failed with status %d: %s",
				res.StatusCode,
				string(body),
			)
		}

		var grant struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
		}
		if err := json.UnmarshalRead(res.Body, &grant); err != nil {
			return "", time.Time{}, fmt.Errorf(
				"failed to decode oauth response: %w",
				err,
			)
		}

		return grant.AccessToken, cfg.clock().
				Add(time.Duration(grant.ExpiresIn) * time.Second),
			nil
	}
	s.source = token.NewSource(
		fetch,
		token.WithBufferTime(60*time.Second),
		token.WithClock(cfg.clock),
	)

	return s
}

// Send dispatches the HTTP request to the FCM v1 API.
func (s *Sender) Send(ctx context.Context, msg *push.Message) error {
	if err := msg.Validate(); err != nil {
		return err
	}

	tok, err := s.source.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to obtain oauth token: %w", err)
	}

	out := map[string]any{}
	if msg.Target.Token != "" {
		out["token"] = msg.Target.Token
	} else if msg.Target.Topic != "" {
		out["topic"] = msg.Target.Topic
	}

	if !msg.Silent {
		out["notification"] = map[string]any{
			"title": msg.Title,
			"body":  msg.Body,
		}
	}

	if len(msg.Data) > 0 {
		out["data"] = msg.Data
	}

	android := map[string]any{}
	headers := map[string]string{}

	if msg.Silent {
		android["priority"] = "NORMAL"
		headers["apns-priority"] = "5"
	} else if msg.Priority == push.PriorityNormal {
		android["priority"] = "NORMAL"
		headers["apns-priority"] = "5"
	} else if msg.Priority == push.PriorityHigh {
		android["priority"] = "HIGH"
		headers["apns-priority"] = "10"
	}

	if msg.CollapseID != "" {
		android["collapse_key"] = msg.CollapseID
		headers["apns-collapse-id"] = msg.CollapseID
	}

	if msg.TTL > 0 {
		android["ttl"] = fmt.Sprintf("%ds", int(msg.TTL.Seconds()))
		exp := s.clock().Add(msg.TTL).Unix()
		headers["apns-expiration"] = fmt.Sprintf("%d", exp)
	}

	if len(android) > 0 {
		out["android"] = android
	}
	if len(headers) > 0 {
		out["apns"] = map[string]any{
			"headers": headers,
		}
	}

	payload := map[string]any{
		"message": out,
	}

	var buf bytes.Buffer
	if err := json.MarshalWrite(&buf, payload); err != nil {
		return fmt.Errorf("failed to encode FCM payload: %w", err)
	}

	endpoint, err := url.JoinPath(
		s.url,
		"projects",
		s.projectID,
		"messages:send",
	)
	if err != nil {
		return fmt.Errorf("invalid endpoint: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &buf)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")

	s.logger.DebugContext(ctx, "Dispatching FCM message",
		slog.String("project", s.projectID),
		slog.Any("target", msg.Target),
	)

	start := s.clock()
	res, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	delta := time.Since(start)

	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		if err := res.Body.Close(); err != nil {
			s.logger.WarnContext(
				ctx,
				"Failed to close response body",
				slog.Any("error", err),
			)
		}
	}()

	if res.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		return &push.APIError{
			Status: res.StatusCode,
			Body:   string(body),
		}
	}

	s.logger.DebugContext(
		ctx,
		"FCM message dispatched",
		slog.Duration("duration", delta),
	)
	return nil
}
