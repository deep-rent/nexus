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

// Package apns provides an Apple Push Notification service (APNs) provider.
//
// It implements the [push.Sender] interface for delivering remote
// notifications to Apple devices using HTTP/2 and JWT authentication.
//
// # Usage
//
// Create a sender by providing your ES256 key ID, Apple team ID, and the
// PEM-encoded PKCS#8 private key contents.
//
//	sender := apns.New(
//		http.DefaultClient,
//		apns.Credentials{
//			KeyID:      "4F92S8D7W1",
//			TeamID:     "8M349Z7F2A",
//			PrivateKey: key, // PEM format
//		},
//		apns.WithBaseURL(apns.SandboxBaseURL),
//	)
//	err := sender.Send(ctx, msg)
package apns

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"time"

	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/push"
	"github.com/deep-rent/nexus/sign"
	"github.com/deep-rent/nexus/token"
)

const (
	// DefaultBaseURL is the production endpoint for APNs.
	DefaultBaseURL = "https://api.push.apple.com"
	// SandboxBaseURL is the sandbox endpoint for APNs.
	SandboxBaseURL = "https://api.sandbox.push.apple.com"
)

// Sender implements the [push.Sender] interface for the Apple Push Notification
// service (APNs). It handles authentication, payload construction, and
// dispatching of push notifications to APNs endpoints.
type Sender struct {
	source *token.Source
	url    string
	client *http.Client
	logger *slog.Logger
	clock  func() time.Time
}

var _ push.Sender = (*Sender)(nil)

type config struct {
	baseURL string
	logger  *slog.Logger
	clock   func() time.Time
}

// Option defines the functional option pattern for configuring the APNs sender.
type Option func(*config)

// WithBaseURL allows overriding the APNs API base URL.
// Useful for switching to [SandboxBaseURL] or mocking.
// Empty string values are ignored.
func WithBaseURL(url string) Option {
	return func(cfg *config) {
		if url != "" {
			cfg.baseURL = url
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

// Credentials contains the necessary credentials for authenticating with APNs.
type Credentials struct {
	// KeyID specifies the ES256 key ID from your Apple Developer account.
	KeyID string
	// TeamID is your Apple team ID.
	TeamID string
	// PrivateKey stores the PEM-encoded PKCS#8 private key contents.
	PrivateKey []byte
}

// New creates a configured Apple Push Notification Service client implementing
// the [push.Sender] interface. It requires the ES256 keyID, your Apple teamID,
// and the PEM-encoded PKCS#8 private key contents.
func New(
	client *http.Client,
	cred Credentials,
	opts ...Option,
) push.Sender {
	signer, err := sign.Decode(cred.PrivateKey)
	if err != nil {
		panic(fmt.Errorf("failed to parse APNs private key: %w", err))
	}

	key := jwk.NewKeyPair(jwa.ES256, cred.KeyID, signer)

	cfg := config{
		baseURL: DefaultBaseURL,
		logger:  slog.Default(),
		clock:   time.Now,
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	fetch := func(ctx context.Context) (string, time.Time, error) {
		claims := struct {
			jwt.Reserved
		}{
			Iss: cred.TeamID,
			Iat: cfg.clock(),
		}
		tok, err := jwt.Sign(ctx, key, claims)
		if err != nil {
			return "", time.Time{}, err
		}
		// Apple allows tokens to be used between 20 and 60 minutes.
		return string(tok), cfg.clock().Add(45 * time.Minute), nil
	}

	source := token.NewSource(
		fetch,
		token.WithBufferTime(5*time.Minute),
		token.WithClock(cfg.clock),
	)

	s := &Sender{
		source: source,
		url:    cfg.baseURL,
		logger: cfg.logger,
		client: client,
		clock:  cfg.clock,
	}

	return s
}

// Send dispatches the HTTP/2 request to the APNs API.
func (s *Sender) Send(ctx context.Context, msg *push.Message) error {
	if err := msg.Validate(); err != nil {
		return err
	}
	if msg.Target.Token == "" {
		return errors.New("APNs requires a device token target")
	}

	tok, err := s.source.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to get APNs token: %w", err)
	}

	payload := make(map[string]any)
	maps.Copy(payload, msg.Data)
	aps := make(map[string]any)
	if msg.Silent {
		aps["content-available"] = 1
	} else {
		aps["alert"] = map[string]any{
			"title": msg.Title,
			"body":  msg.Body,
		}
	}
	payload["aps"] = aps

	var buf bytes.Buffer
	if err := json.MarshalWrite(&buf, payload); err != nil {
		return fmt.Errorf("failed to encode APNs payload: %w", err)
	}

	endpoint, err := url.JoinPath(s.url, "3/device", msg.Target.Token)
	if err != nil {
		return fmt.Errorf("invalid endpoint: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &buf)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	if msg.Target.Topic != "" {
		req.Header.Set("apns-topic", msg.Target.Topic)
	}

	if msg.Silent {
		req.Header.Set("apns-push-type", "background")
		req.Header.Set("apns-priority", "5")
	} else {
		req.Header.Set("apns-push-type", "alert")
		if msg.Priority == push.PriorityNormal {
			req.Header.Set("apns-priority", "5")
		} else {
			req.Header.Set("apns-priority", "10") // Default for alert
		}
	}

	if msg.CollapseID != "" {
		req.Header.Set("apns-collapse-id", msg.CollapseID)
	}

	if msg.TTL > 0 {
		exp := s.clock().Add(msg.TTL).Unix()
		req.Header.Set("apns-expiration", fmt.Sprintf("%d", exp))
	} else {
		req.Header.Set("apns-expiration", "0")
	}

	s.logger.DebugContext(
		ctx,
		"Dispatching APNs message",
		slog.String("token", msg.Target.Token),
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
		"APNs message dispatched",
		slog.Duration("duration", delta),
	)
	return nil
}
